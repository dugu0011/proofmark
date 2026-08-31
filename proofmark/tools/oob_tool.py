"""Tools for out-of-band confirmation of blind vulnerabilities.

Pair them: `oob_canary` mints a unique URL to plant in a payload; `oob_check`
tells you whether the target reached it. A recorded interaction is the proof that
turns "possible blind SSRF" into a confirmed finding.
"""
from __future__ import annotations

from proofmark.oob import InteractionServer
from proofmark.tools.base import Tool, ToolResult


class OobCanaryTool(Tool):
    name = "oob_canary"
    description = (
        "Mint a unique out-of-band canary to PROVE a blind vulnerability — blind SSRF, blind "
        "command injection, XXE that exfiltrates, or blind SQL injection. Returns an HTTP URL and "
        "a DNS hostname. Plant one in your payload (an SSRF target, a `curl`/`nslookup`/`wget` "
        "argument, an XML external entity, a stacked SQL call), trigger it, then call oob_check "
        "with the returned token. If the target calls home, you have proof."
    )
    parameters = {
        "type": "object",
        "properties": {
            "hint": {"type": "string",
                     "description": "Optional label for what you're testing, e.g. 'ssrf on /fetch?url='."},
        },
    }

    def __init__(self, server: InteractionServer) -> None:
        self._server = server

    def run(self, hint: str = "", **_) -> ToolResult:
        token = self._server.new_canary(hint)
        return ToolResult(
            "Out-of-band canary minted. Plant one of these in your payload, trigger it, then call "
            "oob_check with the token.\n"
            f"  token:    {token}\n"
            f"  http url: {self._server.http_url(token)}\n"
            f"  dns host: {self._server.dns_host(token)}",
            data={"token": token},
        )


class OobCheckTool(Tool):
    name = "oob_check"
    description = (
        "Check whether the target reached your out-of-band canary — the confirmation of a blind "
        "vulnerability. Pass the token from oob_canary. Any recorded interaction proves the target "
        "executed your payload out of band; record a finding citing it as evidence. If there is "
        "nothing yet, re-trigger the payload (give it a few seconds) and check again."
    )
    parameters = {
        "type": "object",
        "properties": {
            "token": {"type": "string", "description": "The canary token returned by oob_canary."},
        },
        "required": ["token"],
    }
    # Interaction details (Host, path, User-Agent, body) are target-controlled.
    returns_untrusted_data = True

    def __init__(self, server: InteractionServer) -> None:
        self._server = server

    def run(self, token: str = "", **_) -> ToolResult:
        token = (token or "").strip()
        if not token:
            return ToolResult("Provide the canary token returned by oob_canary.", is_error=True)
        hits = self._server.interactions(token)
        if not hits:
            return ToolResult(
                f"No out-of-band interactions yet for {token}. The target has not called home — "
                "the payload may not have executed, was filtered, or needs more time. Re-trigger "
                "and check again."
            )
        lines = "\n".join(f"  {h.summary()}" for h in hits[:20])
        return ToolResult(
            f"CONFIRMED — {len(hits)} out-of-band interaction(s) for {token}:\n{lines}\n"
            "This proves the target executed your payload out of band. Record the finding with "
            "this as the proof.",
            data={"token": token, "count": len(hits)},
        )
