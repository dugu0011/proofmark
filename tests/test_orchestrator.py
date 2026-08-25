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
