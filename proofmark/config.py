"""Run configuration: what to test, with which model, under what budget.

The model string picks the provider (litellm reads the matching API key from the
environment), so 'anthropic/...' needs ANTHROPIC_API_KEY, 'openai/...' needs
OPENAI_API_KEY, and so on.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

# The default model. Override with PROOFMARK_MODEL so Azure/OpenAI users can set
# their model once (in the shell / .zshrc) instead of passing --model every run.
DEFAULT_MODEL = os.getenv("PROOFMARK_MODEL", "anthropic/claude-sonnet-4-6")

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
    # Optional split-brain models for the recon->exploit graph: a fast/cheap model
    # can map the surface while a stronger one does the reasoning-heavy exploitation.
    # Empty means "use `model` for that phase too".
    recon_model: str = ""
    exploit_model: str = ""
    api_base: str = ""
    operator: str = ""
    allow_hosts: list[str] = field(default_factory=list)
    max_steps: int = 40
    time_budget_seconds: int = 600
    output_path: str = ""
    # Safe mode blocks destructive HTTP methods (PUT/PATCH/DELETE) so the agent can
    # run against production without risk of altering data. On by default.
    safe_mode: bool = True
    # Out-of-band listener for proving blind vulnerabilities (SSRF/RCE/XXE/SQLi).
    # public_host/base override what the target should reach; blank = detected LAN IP.
    oob_enabled: bool = True
    oob_bind_host: str = "0.0.0.0"
    oob_bind_port: int = 0
    oob_public_host: str = ""
    oob_public_base: str = ""

    @staticmethod
    def key_env_var_for(model: str) -> str | None:
        for prefix, var in _PROVIDER_PREFIXES.items():
            if model.startswith(prefix):
                return var
        for alias, var in _PROVIDER_ALIASES.items():
            if alias in model:
                return var
        return None

    def key_env_var(self) -> str | None:
        return self.key_env_var_for(self.model)

    def models_in_use(self) -> list[str]:
        """Every distinct model this run will actually invoke."""
        return list(dict.fromkeys(m for m in (
            self.model, self.recon_model, self.exploit_model) if m))

    def missing_key(self) -> str | None:
        """The env var some chosen model needs but that is not set. None if fine."""
        for model in self.models_in_use():
            var = self.key_env_var_for(model)
            if var and not os.environ.get(var):
                return var
        return None
