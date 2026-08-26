"""subdomains: passive subdomain discovery from Certificate Transparency logs.

Lists what exists for the target's domain without touching any of it. Names that
fall inside the authorized scope are marked testable; the rest are intelligence
the operator can choose to authorize.
"""
from __future__ import annotations

import json

from proofmark.authorization import Authorization
from proofmark.osint import CRTSH, parse_crtsh, registered_domain
from proofmark.sandbox import Sandbox
from proofmark.tools.base import Tool, ToolResult


class SubdomainTool(Tool):
    name = "subdomains"
    returns_untrusted_data = True
    description = (
        "Discover subdomains of the target's domain passively, from public "
        "Certificate Transparency logs. Does not probe the subdomains. Names in the "
        "authorized scope are testable; others are shown for the operator to allow."
    )
    parameters = {
        "type": "object",
        "properties": {"domain": {"type": "string", "description": "Domain to search. Defaults to the target's."}},
    }

    def __init__(self, sandbox: Sandbox, authorization: Authorization) -> None:
        self._sb = sandbox
        self._auth = authorization

    def run(self, **kwargs) -> ToolResult:
        host = kwargs.get("domain") or self._auth.target
        domain = registered_domain(host)
        if not domain:
            return ToolResult("Could not determine a domain to search.", is_error=True)

        spec = json.dumps({"method": "GET", "url": CRTSH.format(domain=domain), "timeout": 25})
        code, out = self._sb.exec(["python", self._sb.runner_path, spec], timeout=35)
        try:
            data = json.loads(out.strip())
            body = data.get("body", "")
        except ValueError:
            return ToolResult("Could not reach the CT log (crt.sh).", is_error=True)

        subs = sorted(parse_crtsh(body, domain))
        if not subs:
            return ToolResult(f"No subdomains found for {domain} in CT logs.")

        in_scope = [s for s in subs if self._auth.permits_host(s)]
        out_scope = [s for s in subs if s not in in_scope]
        lines = [f"{len(subs)} subdomain(s) of {domain} from CT logs:"]
        if in_scope:
            lines.append("In scope (you may test these):")
            lines += [f"  ✓ {s}" for s in in_scope]
        if out_scope:
            lines.append("Not in scope (add with --allow-host to test):")
            lines += [f"  • {s}" for s in out_scope[:40]]
        return ToolResult("\n".join(lines))
