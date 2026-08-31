"""Subdomain takeover detection.

A subdomain whose DNS CNAME points at a third-party service (GitHub Pages, S3,
Heroku, …) that has since been deleted is claimable: an attacker registers the
resource and serves content on your subdomain. The tell is the service's own
"unclaimed / not found" page. This fetches the host and matches those fingerprints.
"""
from __future__ import annotations

import re

from proofmark.http_client import Request
from proofmark.tools.base import Tool, ToolResult

_FINGERPRINTS = [
    ("GitHub Pages", re.compile(r"There isn't a GitHub Pages site here", re.I)),
    ("AWS S3", re.compile(r"NoSuchBucket|The specified bucket does not exist", re.I)),
    ("Heroku", re.compile(r"No such app|no-such-app", re.I)),
    ("Amazon CloudFront", re.compile(r"ERROR: The request could not be satisfied", re.I)),
    ("Fastly", re.compile(r"Fastly error: unknown domain", re.I)),
    ("Shopify", re.compile(r"Sorry, this shop is currently unavailable", re.I)),
    ("Tumblr", re.compile(r"Whatever you were looking for doesn't currently exist", re.I)),
    ("Zendesk", re.compile(r"this help center no longer exists|Help Center Closed", re.I)),
    ("Ghost", re.compile(r"The thing you were looking for is no longer here", re.I)),
    ("Surge.sh", re.compile(r"project not found", re.I)),
    ("Bitbucket", re.compile(r"Repository not found", re.I)),
    ("Pantheon", re.compile(r"404 error unknown site|The gods are wise", re.I)),
    ("Netlify", re.compile(r"Not Found - Request ID", re.I)),
    ("Read the Docs", re.compile(r"unknown to Read the Docs", re.I)),
    ("Azure", re.compile(r"404 Web Site not found", re.I)),
    ("Wordpress.com", re.compile(r"Do you want to register", re.I)),
]


class SubdomainTakeoverTool(Tool):
    name = "subdomain_takeover_test"
    description = (
        "Check a (sub)domain for takeover: fetch it and match the response against the 'unclaimed / "
        "not found' pages of common hosting services (GitHub Pages, S3, Heroku, Fastly, Netlify, …). "
        "A match means a dangling CNAME may point to a resource an attacker can register and control. "
        "Give the host or URL (must be in scope — add --allow-host for other subdomains)."
    )
    parameters = {"type": "object",
                  "properties": {"url": {"type": "string", "description": "Host or URL to check."}},
                  "required": ["url"]}
    returns_untrusted_data = True

    def __init__(self, client) -> None:
        self._client = client

    def run(self, url="", **_) -> ToolResult:
        target = url if url.startswith(("http://", "https://")) else f"https://{url}"
        _o, _t, ex = self._client.send(Request("GET", target, {}))
        if ex is None or ex.status is None:
            return ToolResult(f"Could not reach {target} (host may not resolve — a dangling record "
                              "still worth checking in DNS).")
        body = ex.response_preview or ""
        for service, sig in _FINGERPRINTS:
            m = sig.search(body)
            if m:
                return ToolResult(
                    f"POTENTIAL SUBDOMAIN TAKEOVER (high) at {target}: the response matches an "
                    f"unclaimed {service} endpoint ({m.group(0)!r}). If a DNS CNAME points here and "
                    f"the {service} resource is unregistered, an attacker can claim it and serve "
                    "content on this subdomain. Confirm the CNAME is dangling (dig/host), then record.")
        return ToolResult(f"No takeover fingerprint at {target} (HTTP {ex.status}). It serves normal "
                          "content or a generic error, not a claimable third-party service page.")
