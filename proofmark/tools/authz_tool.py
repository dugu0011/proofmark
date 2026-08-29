"""Test broken access control by replaying one request as other principals.

BOLA/IDOR and BFLA are the same move: take a request the current user is allowed
to make, resend it *as someone who should not be allowed*, and see whether the
server enforces the boundary. This tool automates that move — give it a request
you already sent, and it replays it as every other identity available (a second
user, an admin, or anonymous) and lays the responses side by side.

The comparison is the evidence: if a lower-privileged identity gets the same 2xx
body the owner got, the object/function is not access-controlled. Each replay is
logged like any other request, so the exact exchanges can go straight into a
finding's proof-of-concept.
"""
from __future__ import annotations

from proofmark.http_client import HttpClient
from proofmark.tools.base import Tool, ToolResult


def _looks_allowed(status: int | None) -> bool:
    return status is not None and 200 <= status < 300


class AuthzProbeTool(Tool):
    name = "authz_probe"
    returns_untrusted_data = True
    description = (
        "Test broken access control (BOLA/IDOR and BFLA). Give the number of a "
        "request you already sent (from list_requests) that reads an object or "
        "invokes a privileged action, and this resends it as every other identity "
        "— a second user, an admin, or anonymous — and compares the responses. "
        "If a lower-privileged identity gets the same successful response, access "
        "control is broken; confirm the returned data belongs to the other "
        "principal, then record_finding with these request numbers as the proof."
    )
    parameters = {
        "type": "object",
        "properties": {
            "index": {"type": "integer", "description": "Request number to replay (from list_requests)."},
            "identities": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Which identities to replay as. Omit to try all available.",
            },
        },
        "required": ["index"],
    }

    def __init__(self, client: HttpClient) -> None:
        self._client = client

    def run(self, **kwargs) -> ToolResult:
        original = self._client.log.get(int(kwargs.get("index", -1)))
        if original is None:
            return ToolResult("No request with that number. Use list_requests first.", is_error=True)

        available = self._client.alternate_identities()
        requested = kwargs.get("identities") or available
        identities = [i for i in requested if i in available]
        if not identities:
            return ToolResult(
                "No alternate identity is configured for this run, so access control "
                "can only be compared against 'anonymous'. Re-run the pentest with a "
                "second set of credentials to test one user reaching another's data.",
                is_error=True,
            )

        base = original.request
        base_status = original.status
        base_len = len(original.response_preview or "")

        lines = [
            f"Access-control probe of request #{original.index}: "
            f"{base.method} {base.url}",
            f"  as primary        -> HTTP {base_status}  ({base_len} bytes)  [the owner]",
        ]
        flagged: list[str] = []
        for name in identities:
            ok, _text, ex = self._client.send(base, identity=name)
            label = self._client.identity_label(name)
            size = len(ex.response_preview or "")
            note = ""
            if _looks_allowed(ex.status) and _looks_allowed(base_status):
                # Same object reachable by someone who is not the owner.
                similar = base_len == 0 or abs(size - base_len) <= max(40, base_len * 0.2)
                if similar:
                    note = "  <-- SAME success as owner: likely broken access control"
                    flagged.append(name)
                else:
                    note = "  <-- allowed, but body differs; check whose data this is"
                    flagged.append(name)
            elif ex.status in (401, 403):
                note = "  (denied — access control holding for this identity)"
            elif ex.status == 404:
                note = "  (404 — hidden or not found; not conclusive)"
            lines.append(f"  as {label:<18}-> HTTP {ex.status}  ({size} bytes)  [replay #{ex.index}]{note}")

        if flagged:
            lines.append("")
            lines.append(
                "A non-owner identity got a successful response. If that body contains "
                "the other principal's data (or performs their privileged action), this "
                "is Broken Access Control (BOLA/IDOR for an object, BFLA for a function). "
                "Verify the data belongs to them, then record_finding citing these "
                "request numbers as the proof-of-concept."
            )
        else:
            lines.append("")
            lines.append("Every other identity was denied — access control looks enforced here.")
        return ToolResult("\n".join(lines))
