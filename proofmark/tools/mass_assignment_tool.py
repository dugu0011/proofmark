"""Test mass assignment: does a write accept fields the client should not set?

Mass assignment (a.k.a. auto-binding / object injection) is when an endpoint
binds a request body straight onto a model, so sending an extra field the UI
never exposes — role, is_admin, verified, account balance — silently sets it.
The move to prove it: take a write request you already sent, add the privileged
field, resend, and check whether the server accepted it (echoed it back, or a
follow-up read shows it changed).

This tool automates the "add the field and resend" half against a JSON body and
reports whether the injected fields come back in the response — a strong signal
they were bound. Confirm with a read, then record_finding.
"""
from __future__ import annotations

import json

from proofmark.http_client import HttpClient, Request
from proofmark.tools.base import Tool, ToolResult

# Fields a client should never be able to set on itself — the usual privilege and
# trust flags. Used when the agent does not name its own.
_DEFAULT_FIELDS = {
    "role": "admin", "is_admin": True, "isAdmin": True, "admin": True,
    "is_staff": True, "is_superuser": True, "verified": True,
    "is_verified": True, "email_verified": True, "account_type": "admin",
}


class MassAssignmentTool(Tool):
    name = "mass_assignment_probe"
    returns_untrusted_data = True
    description = (
        "Test mass assignment / auto-binding. Give the number of a write request "
        "you already sent (POST/PUT/PATCH with a JSON body), and this resends it "
        "with extra privileged fields added to the body (role, is_admin, verified, "
        "…) and reports whether the server echoed them back — a sign it bound them. "
        "You can override the fields to inject. Confirm the change with a read, "
        "then record_finding."
    )
    parameters = {
        "type": "object",
        "properties": {
            "index": {"type": "integer", "description": "The write request number (from list_requests)."},
            "fields": {
                "type": "object",
                "description": "Fields to inject into the body. Omit to use the common privileged set.",
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

        base = original.request
        if not base.body:
            return ToolResult(
                "That request has no body to inject into. Mass assignment needs a JSON "
                "write (POST/PUT/PATCH); send one first, then probe it.",
                is_error=True,
            )
        try:
            body = json.loads(base.body)
        except (TypeError, ValueError):
            return ToolResult(
                "That request's body is not JSON, so there are no fields to add. Mass "
                "assignment here needs a JSON write body.",
                is_error=True,
            )
        if not isinstance(body, dict):
            return ToolResult("The request body is JSON but not an object, so there are no fields to add.",
                              is_error=True)

        inject = kwargs.get("fields") or _DEFAULT_FIELDS
        tampered = {**body, **inject}
        req = Request(base.method, base.url, base.headers, json.dumps(tampered))
        ok, _text, ex = self._client.send(req)
        if not ok:
            return ToolResult(
                f"The write could not be sent (HTTP {ex.status}, {ex.error or 'no response'}). "
                "Note: safe mode blocks PUT/PATCH/DELETE — a create (POST) is the usual way to "
                "prove mass assignment without changing existing data.",
                is_error=True,
            )

        response = ex.response_preview or ""
        reflected = [k for k in inject if f'"{k}"' in response]
        lines = [
            f"Injected {list(inject)} into request #{original.index} "
            f"({base.method} {base.url}) -> replay #{ex.index}: HTTP {ex.status}",
        ]
        if reflected:
            lines.append(
                f"The response echoes the injected field(s): {reflected}. The server likely "
                "bound them. Read the object back to confirm the privileged value stuck, then "
                "record_finding (mass assignment, A03/A08) citing these request numbers."
            )
        else:
            lines.append(
                "None of the injected fields came back in the response. Not conclusive — the "
                "field may still be bound silently. Read the object back and compare before "
                "deciding."
            )
        return ToolResult("\n".join(lines))
