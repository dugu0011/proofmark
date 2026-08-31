"""GraphQL testing — introspection exposure and a scan for sensitive operations.

Introspection left on hands an attacker the full schema, including admin/user
mutations that should never be reachable. This posts the introspection query and,
if the schema comes back, flags the sensitive types and mutations to target."""
from __future__ import annotations

import re

from proofmark.http_client import Request
from proofmark.tools.base import Tool, ToolResult

_INTROSPECTION = (
    '{"query":"query{__schema{queryType{name} mutationType{name} '
    'types{name kind fields{name}}}}"}'
)
_SENSITIVE = re.compile(
    r"(?i)(user|password|passwd|token|secret|admin|role|permission|create\w*|update\w*|"
    r"delete\w*|register|login|reset|credential|apikey|api_key|payment|invoice)")


class GraphQLTool(Tool):
    name = "graphql_test"
    description = (
        "Probe a GraphQL endpoint. Runs the introspection query; if the schema comes back, "
        "introspection is enabled (a misconfiguration) and the tool lists the exposed types, "
        "fields, and mutations — flagging the sensitive ones (user/admin/create*/delete*/token) "
        "worth attacking next. Give the GraphQL url (usually /graphql)."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "The GraphQL endpoint URL."},
        },
        "required": ["url"],
    }
    returns_untrusted_data = True

    def __init__(self, client) -> None:
        self._client = client

    def run(self, url="", **_) -> ToolResult:
        _ok, _t, ex = self._client.send(
            Request("POST", url, {"Content-Type": "application/json"}, _INTROSPECTION))
        body = (ex.response_preview if ex else "") or ""
        if "__schema" not in body and "queryType" not in body and '"types"' not in body:
            return ToolResult("Introspection did not return a schema — it may be disabled, or this "
                              "is not a GraphQL endpoint. (Try field-suggestion probing instead.)")
        names = sorted(set(re.findall(r'"name"\s*:\s*"(\w+)"', body)))
        sensitive = [n for n in names if _SENSITIVE.search(n)]
        summary = (f"GRAPHQL INTROSPECTION ENABLED (misconfiguration). {len(names)} named "
                   f"types/fields exposed.")
        if sensitive:
            summary += ("\nSensitive names to target: " + ", ".join(sensitive[:25]) +
                        ("…" if len(sensitive) > 25 else "") +
                        "\nProbe these for broken authorization (call a mutation as a low-priv user).")
        return ToolResult(summary, data={"names": names, "sensitive": sensitive})
