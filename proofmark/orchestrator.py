"""A graph of agents: specialized roles that hand work to each other.

Rather than one generalist doing everything, the work is split into phases, each
an agent with its own brief and its own tools, sharing a blackboard. The recon
agent maps the surface and writes down what it found; the exploit agent starts
from that map and proves what it can. More phases can be added — the pattern is
the same: each reads the blackboard, works, and writes back.

This is deliberately sequential and bounded. An autonomous agent that exploits
needs hard stops it cannot argue with, and a graph of them needs them more, not
less — so every phase carries its own step budget and the whole run carries the
authorization gate and the signed record unchanged.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from proofmark.agent import Agent, Event, Outcome
from proofmark.authorization import Authorization
from proofmark.blackboard import Blackboard
from proofmark.llm import LLM
from proofmark.tools.base import Tool, ToolRegistry


@dataclass
class Phase:
    name: str
    role_prompt: str
    tools: list[Tool]
    max_steps: int = 20


class Coordinator:
    def __init__(
        self,
        llm: LLM,
        authorization: Authorization,
        *,
        name: str,
        phases: list[Phase],
        blackboard: Blackboard,
        time_budget_seconds: int = 900,
        on_event: Callable[[Event], None] | None = None,
        steer_fn: Callable[[], list[str]] | None = None,
    ) -> None:
        self._llm = llm
        self._auth = authorization
        self._name = name
        self._phases = phases
        self._bb = blackboard
        self._deadline = time.time() + time_budget_seconds
        self._emit = on_event or (lambda e: None)
        self._steer = steer_fn

    def run(self, target: str, kind: str) -> Outcome:
        total_steps = 0
        stopped = "graph complete"
        for phase in self._phases:
            if time.time() > self._deadline:
                stopped = "time budget exhausted"
                self._emit(Event("done", "Stopping the graph: time budget reached."))
                break

            self._emit(Event("think", f"── agent: {phase.name} ──"))
            suffix = phase.role_prompt
            brief = self._bb.briefing()
            if brief:
                suffix += "\n\n" + brief

            remaining = max(1, int(self._deadline - time.time()))
            agent = Agent(
                self._llm, ToolRegistry(phase.tools), self._auth,
                name=f"{self._name}:{phase.name}",
                system_suffix=suffix, max_steps=phase.max_steps,
                time_budget_seconds=remaining, on_event=self._emit, steer_fn=self._steer,
            )
            outcome = agent.run(target, kind)
            total_steps += outcome.steps_used
            # New findings from this phase join the shared board for the next one.
            for f in outcome.findings:
                if f not in self._bb.findings:
                    self._bb.findings.append(f)

        return Outcome(
            findings=list(self._bb.findings),
            summary=f"{len(self._phases)}-agent graph over {target}.",
            steps_used=total_steps,
            stopped_reason=stopped,
        )


# ------------------------------------------------------------------ role prompts
RECON_ROLE = (
    "You are the RECON agent in a team. Your ONLY job is to map the target: "
    "endpoints, forms and their parameters, the tech stack, auth scheme, and any "
    "exposed paths. DO NOT try to exploit anything. Record everything useful with "
    "the `note` tool so the exploitation agent that follows can act on it, then "
    "call finish. Be thorough but quick."
)

EXPLOIT_ROLE = (
    "You are the EXPLOITATION agent. The recon agent has already mapped the target "
    "for you (see below). Use that map to find and PROVE vulnerabilities — test "
    "hypotheses, reproduce them, and record only what you can prove with a "
    "proof-of-concept. Prioritize the highest-impact classes first."
)
