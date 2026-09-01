"""Race-condition (TOCTOU) testing.

Some actions must happen once — redeem a coupon, withdraw a balance, accept an
invite. If the endpoint checks-then-acts without a lock, firing many identical
requests at the same instant can slip several through the window. This sends N
concurrent identical requests and reports how many succeeded: more than one is a
strong signal of a race the agent should confirm against the business rule.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from proofmark.http_client import Request
from proofmark.tools.base import Tool, ToolResult


class RaceConditionTool(Tool):
    name = "race_condition_test"
    description = (
        "Test a state-changing endpoint for a race condition (TOCTOU). Fires N identical requests "
        "concurrently; if more than one succeeds where the action should only happen once (redeem, "
        "withdraw, apply-once), the endpoint isn't serializing access — a race window. Use on "
        "POST/PUT actions while authenticated. Give url, method, body, and optionally count."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "The state-changing endpoint."},
            "method": {"type": "string", "description": "HTTP method (default POST)."},
            "body": {"type": "string", "description": "Request body to submit each time."},
            "count": {"type": "integer", "description": "How many concurrent requests (default 20, max 50)."},
        },
        "required": ["url"],
    }
    returns_untrusted_data = True

    def __init__(self, client) -> None:
        self._client = client

    def run(self, url="", method="POST", body=None, count=20, **_) -> ToolResult:
        method = (method or "POST").upper()
        n = min(max(int(count or 20), 2), 50)
        headers = {"Content-Type": "application/x-www-form-urlencoded"} if body else {}

        def one(_):
            _o, _t, ex = self._client.send(Request(method, url, dict(headers), body))
            return ex.status if ex else None

        with ThreadPoolExecutor(max_workers=n) as pool:
            statuses = list(pool.map(one, range(n)))
        ok = sum(1 for s in statuses if s and 200 <= s < 300)

        if ok >= 2:
            return ToolResult(
                f"POSSIBLE RACE CONDITION on {method} {url} (medium): {ok} of {n} concurrent "
                "identical requests succeeded (2xx). If this action is meant to happen only once "
                "(coupon redeem, withdrawal, invite accept), the endpoint isn't serializing access "
                "— confirm the duplicated effect (e.g. balance debited once but credited twice), "
                "then record it.")
        return ToolResult(
            f"No race detected on {method} {url}: only {ok} of {n} concurrent requests succeeded — "
            "the endpoint appears to serialize access (lock / unique constraint).")
