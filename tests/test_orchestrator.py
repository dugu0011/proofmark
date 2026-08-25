"""The graph of agents, driven by a scripted fake model so it runs offline.

Pins the behaviour that makes multi-agent worth more than one agent: the recon
agent's notes reach the exploit agent, and findings from all phases aggregate.
"""
from proofmark.authorization import Authorization
from proofmark.blackboard import Blackboard
from proofmark.llm import Completion
from proofmark.orchestrator import Coordinator, EXPLOIT_ROLE, Phase, RECON_ROLE
from proofmark.tools.note_tool import NoteTool
from proofmark.tools.record_finding import RecordFindingTool


class ScriptedLLM:
    """Returns queued replies; records the system prompt each agent was given."""

    def __init__(self, scripts):
        self._scripts = list(scripts)
        self.systems_seen = []

    def complete(self, messages, tools) -> Completion:
        # capture the system prompt so tests can assert what each agent knew
        self.systems_seen.append(messages[0]["content"])
        step = self._scripts.pop(0)
        calls = [{"id": f"c{i}", "name": n, "arguments": a} for i, (n, a) in enumerate(step)]
        return Completion(text="", tool_calls=calls,
                          raw_message={"role": "assistant", "content": "", "tool_calls": []})


def test_recon_notes_reach_the_exploit_agent_and_findings_aggregate():
    import json
    bb = Blackboard()
    auth = Authorization.grant("https://app.test", "tester")

    # recon: note an endpoint, then finish. exploit: record a finding, then finish.
    scripts = [
        [("note", json.dumps({"observation": "GET /api/users/{id} reflects id unsanitized"}))],
        [("finish", json.dumps({"summary": "mapped"}))],
        [("record_finding", json.dumps({
            "title": "IDOR on /api/users", "severity": "high", "location": "/api/users/{id}",
            "description": "cross-user read", "proof_of_concept": "GET /api/users/2 -> 200"}))],
        [("finish", json.dumps({"summary": "done"}))],
    ]
    llm = ScriptedLLM(scripts)

    phases = [
        Phase("recon", RECON_ROLE, [NoteTool(bb)], max_steps=3),
        Phase("exploit", EXPLOIT_ROLE, [RecordFindingTool()], max_steps=3),
    ]
    coord = Coordinator(llm, auth, name="Proofmark", phases=phases, blackboard=bb)
    outcome = coord.run("https://app.test", "url")

    # the note recon wrote is in the blackboard...
    assert any("reflects id unsanitized" in n for n in bb.notes)
    # ...and it was injected into the EXPLOIT agent's system prompt
    exploit_system = llm.systems_seen[-2]  # the exploit agent's first call
    assert "reflects id unsanitized" in exploit_system
    assert "EXPLOITATION agent" in exploit_system
    # the finding aggregated into the final outcome
    assert len(outcome.findings) == 1
    assert outcome.findings[0].title == "IDOR on /api/users"


def test_the_recon_agent_is_told_not_to_exploit():
    bb = Blackboard()
    auth = Authorization.grant("https://app.test", "tester")
    import json
    llm = ScriptedLLM([[("finish", json.dumps({"summary": "x"}))]])
    coord = Coordinator(llm, auth, name="Proofmark",
                        phases=[Phase("recon", RECON_ROLE, [NoteTool(bb)], max_steps=2)],
                        blackboard=bb)
    coord.run("https://app.test", "url")
    assert "DO NOT try to exploit" in llm.systems_seen[0]


# --------------------------------------------------------------------------- steering


def test_steering_instructions_are_injected_as_user_turns():
    """An instruction pushed mid-run becomes a user message the agent must act on."""
    import json
    from proofmark.agent import Agent
    from proofmark.authorization import Authorization
    from proofmark.tools.base import ToolRegistry
    from proofmark.tools.record_finding import RecordFindingTool

    auth = Authorization.grant("https://app.test", "tester")

    # Feed one steering instruction before the second step.
    pending = [["focus on /admin now"]]
    def steer():
        return pending.pop(0) if pending else []

    seen_user_turns = []
    class LLM:
        def __init__(self): self.n = 0
        def complete(self, messages, tools):
            from proofmark.llm import Completion
            # capture any operator-instruction user turns
            for m in messages:
                if m.get("role") == "user" and "OPERATOR INSTRUCTION" in str(m.get("content", "")):
                    seen_user_turns.append(m["content"])
            self.n += 1
            if self.n == 1:
                return Completion("", [], {"role": "assistant", "content": ""})  # no tool -> nudge
            return Completion("", [{"id": "c", "name": "finish",
                                    "arguments": json.dumps({"summary": "done"})}],
                              {"role": "assistant", "content": ""})

    agent = Agent(LLM(), ToolRegistry([RecordFindingTool()]), auth, name="Proofmark",
                  max_steps=5, steer_fn=steer)
    agent.run("https://app.test", "url")

    assert any("focus on /admin now" in t for t in seen_user_turns)


def test_events_and_control_files_round_trip(tmp_path):
    """The CLI's live plumbing: events append as JSONL, control lines are read once."""
    import json
    events = tmp_path / "events.jsonl"
    control = tmp_path / "control.txt"

    # emulate the CLI's two closures
    fh = open(events, "a", encoding="utf-8")
    def record(kind, text, detail=""):
        fh.write(json.dumps({"kind": kind, "text": text, "detail": detail}) + "\n"); fh.flush()

    pos = {"n": 0}
    def pull():
        try:
            lines = control.read_text().splitlines()
        except OSError:
            return []
        new = lines[pos["n"]:]; pos["n"] = len(lines)
        return [l for l in new if l.strip()]

    record("action", "http_request", "GET /x")
    control.write_text("look at the login form\n")
    first = pull()
    control.write_text("look at the login form\nnow try SQLi\n")
    second = pull()
    fh.close()

    assert first == ["look at the login form"]
    assert second == ["now try SQLi"]      # only the newly-appended line, read once
    rows = [json.loads(l) for l in events.read_text().splitlines()]
    assert rows[0]["kind"] == "action" and rows[0]["detail"] == "GET /x"
