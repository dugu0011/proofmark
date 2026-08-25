"""Run configuration: what to test, with which model, under what budget.

The model string picks the provider (litellm reads the matching API key from the
environment), so 'anthropic/...' needs ANTHROPIC_API_KEY, 'openai/...' needs
OPENAI_API_KEY, and so on.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

DEFAULT_MODEL = "anthropic/claude-sonnet-4-6"

# Explicit provider prefixes are authoritative and checked first — "azure/gpt-4.1"
# is Azure, not OpenAI, even though it contains "gpt".
_PROVIDER_PREFIXES = {
    "anthropic/": "ANTHROPIC_API_KEY",
    "openai/": "OPENAI_API_KEY",
    "azure/": "AZURE_API_KEY",
}
# Looser aliases, only consulted when no explicit prefix matched.
_PROVIDER_ALIASES = {
    "claude": "ANTHROPIC_API_KEY",
    "gpt": "OPENAI_API_KEY",
}


@dataclass
class RunConfig:
    target: str
    kind: str            # "url" | "repo" | "path"
    model: str = DEFAULT_MODEL
    api_base: str = ""
    operator: str = ""
    allow_hosts: list[str] = field(default_factory=list)
    max_steps: int = 40
    time_budget_seconds: int = 600
    output_path: str = ""

    def key_env_var(self) -> str | None:
        for prefix, var in _PROVIDER_PREFIXES.items():
            if self.model.startswith(prefix):
                return var
        for alias, var in _PROVIDER_ALIASES.items():
            if alias in self.model:
                return var
        return None

    def missing_key(self) -> str | None:
        """The env var the chosen model needs, if it is not set. None if fine."""
        var = self.key_env_var()
        if var and not os.environ.get(var):
            return var
        return None
