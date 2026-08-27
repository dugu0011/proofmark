"""The one place we talk to a model, through litellm so any provider works.

litellm normalizes OpenAI, Anthropic and Azure onto the same tool-calling shape,
and reads the provider's key straight from the environment (OPENAI_API_KEY,
ANTHROPIC_API_KEY, ...). So the tool is provider-agnostic: pick a model string
like 'anthropic/claude-sonnet-4-6' or 'openai/gpt-4o' and set the matching key.
"""
from __future__ import annotations

from dataclasses import dataclass


class LLMError(RuntimeError):
    pass


@dataclass
class Completion:
    """A normalized model reply: some text, and any tool calls it wants to make."""

    text: str
    tool_calls: list[dict]  # [{"id","name","arguments"}]
    raw_message: dict       # the assistant message, to append verbatim to history


class LLM:
    def __init__(self, model: str, *, api_base: str = "", temperature: float = 0.4,
                 max_tokens: int = 2000) -> None:
        self.model = model
        self.api_base = api_base
        self.temperature = temperature
        self.max_tokens = max_tokens
        # Running totals so a run can report what it cost — tokens are exact, the
        # dollar figure is litellm's best estimate from its pricing table.
        self.calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.cost_usd = 0.0

    def usage(self) -> dict:
        return {
            "model": self.model, "calls": self.calls,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.prompt_tokens + self.completion_tokens,
            "cost_usd": round(self.cost_usd, 6),
        }

    def complete(self, messages: list[dict], tools: list[dict]) -> Completion:
        import litellm  # heavy import, kept lazy

        kwargs = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "tool_choice": "auto",
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        if self.api_base:
            kwargs["api_base"] = self.api_base
        try:
            response = litellm.completion(**kwargs)
        except Exception as exc:  # noqa: BLE001 - provider errors are varied
            raise LLMError(f"{type(exc).__name__}: {exc}") from exc

        self.calls += 1
        usage = getattr(response, "usage", None)
        if usage is not None:
            self.prompt_tokens += int(getattr(usage, "prompt_tokens", 0) or 0)
            self.completion_tokens += int(getattr(usage, "completion_tokens", 0) or 0)
        try:
            self.cost_usd += float(litellm.completion_cost(completion_response=response) or 0.0)
        except Exception:  # noqa: BLE001 - pricing is best-effort, never fatal
            pass

        message = response.choices[0].message
        calls = []
        for call in (getattr(message, "tool_calls", None) or []):
            calls.append({
                "id": call.id,
                "name": call.function.name,
                "arguments": call.function.arguments,
            })
        # model_dump() gives the exact dict shape to append back to history.
        raw = message.model_dump() if hasattr(message, "model_dump") else dict(message)
        return Completion(text=(message.content or ""), tool_calls=calls, raw_message=raw)
