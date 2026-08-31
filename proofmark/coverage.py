"""Coverage tracking — make the agent test the OWASP Top 10 systematically.

A strong pentester is thorough, not just clever: it does not leave an endpoint
untested for a whole vulnerability class. This is the bookkeeping that enforces
it — a matrix of (endpoint, check) the agent fills in as it works, and a gaps
view that tells it exactly what it still has to try. Kept simple and in memory;
one board is shared across the run."""
from __future__ import annotations

# The classes worth checking on an endpoint — aligned with the exploit tools so
# the gaps view maps straight onto an action to take.
CHECKS = [
    "bola-idor", "bfla", "sqli", "command-injection", "ssrf", "ssti", "xss", "xxe",
    "path-traversal", "open-redirect", "mass-assignment", "auth-bypass", "jwt",
    "cors", "rate-limit", "graphql-introspection", "sensitive-data-exposure",
]


class CoverageBoard:
    def __init__(self) -> None:
        self._status: dict[tuple[str, str], str] = {}

    def note(self, endpoint: str, check: str, status: str = "tested") -> None:
        self._status[(endpoint.strip(), check.strip().lower())] = status

    def endpoints(self) -> list[str]:
        return sorted({e for e, _ in self._status})

    def gaps(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for e in self.endpoints():
            done = {c for (ee, c) in self._status if ee == e}
            out[e] = [c for c in CHECKS if c not in done]
        return out

    def matrix(self) -> dict[str, dict[str, str]]:
        out: dict[str, dict[str, str]] = {}
        for (e, c), status in self._status.items():
            out.setdefault(e, {})[c] = status
        return out
