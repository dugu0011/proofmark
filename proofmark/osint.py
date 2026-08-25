"""Passive attack-surface discovery that respects scope.

Active subdomain brute-forcing would send requests to hosts the operator never
authorized — the exact thing Proofmark refuses to do. So subdomain discovery here
is *passive*: it reads public Certificate Transparency logs (crt.sh), which lists
certificates issued for a domain, and never touches the subdomains themselves.

Discovered names are reported as intelligence. A name is only testable if it is
in the authorized scope; the rest are shown as "add with --allow-host to test",
so the operator stays in control of what actually gets probed.
"""
from __future__ import annotations

import json

# The one external host this feature queries — a public CT-log search. Fixed, so
# it is a known-safe source, not "reach anywhere".
CRTSH = "https://crt.sh/?q=%25.{domain}&output=json"


def registered_domain(host: str) -> str:
    """A best-effort registrable domain (last two labels).

    Not a full public-suffix-list implementation, so example.co.uk resolves to
    co.uk — good enough to seed a CT search, and the operator sees the result.
    """
    host = (host or "").split("://")[-1].split("/")[0].split(":")[0]
    labels = [l for l in host.split(".") if l]
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def parse_crtsh(json_text: str, domain: str) -> set[str]:
    """Distinct subdomains of `domain` from a crt.sh JSON response."""
    try:
        rows = json.loads(json_text)
    except ValueError:
        return set()
    out: set[str] = set()
    suffix = "." + domain
    for row in rows if isinstance(rows, list) else []:
        value = (row.get("name_value") or "") if isinstance(row, dict) else ""
        for name in value.splitlines():
            name = name.strip().lstrip("*.").lower()
            if name == domain or name.endswith(suffix):
                out.add(name)
    return out
