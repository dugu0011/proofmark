"""The recon tool: map the target's surface before attacking it."""
from __future__ import annotations

from proofmark.http_client import HttpClient
from proofmark.recon import run_recon, summarize
from proofmark.tools.base import Tool, ToolResult


class ReconTool(Tool):
    name = "recon"
    returns_untrusted_data = True
    description = (
        "Map the target's attack surface: crawl same-host links, extract forms and "
        "their parameters, and probe common paths (.env, .git, admin, api). Run this "
        "early to find where to test. Stays within the authorized scope."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Where to start. Defaults to the target root."},
            "probe_paths": {"type": "boolean", "description": "Also probe common paths. Default true."},
        },
        "required": ["url"],
    }

    def __init__(self, client: HttpClient) -> None:
        self._client = client

    def run(self, **kwargs) -> ToolResult:
        url = kwargs.get("url", "")
        if not url:
            return ToolResult("Give a starting URL.", is_error=True)
        surface = run_recon(self._client, url, probe_paths=kwargs.get("probe_paths", True))
        if not surface.pages:
            return ToolResult("Recon could not reach the target (all requests failed or "
                              "were out of scope).", is_error=True)
        return ToolResult(summarize(surface))
