"""The gate. An agent that actively exploits must not be aimed by accident.

A scanner that fires the wrong request is noise. An agent that autonomously
*exploits* the wrong target is an incident. So this tool refuses to run until the
operator asserts, explicitly, that they are authorized to test the target — and
that assertion is recorded in the report, timestamped, so there is a durable
answer to "who authorized this".

This is enforced in code, not merely asked for in the prompt: without the
assertion the run does not start, and a tool that tries to reach a host outside
the declared scope is refused before it leaves the process.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit


@dataclass
class Authorization:
    """A recorded assertion that this run is permitted."""

    target: str
    operator: str
    asserted_at: datetime
    # Hosts the agent may touch. The target's host, plus anything --allow-host adds.
    allowed_hosts: frozenset[str]

    @classmethod
    def grant(cls, target: str, operator: str, extra_hosts: list[str] | None = None) -> "Authorization":
        hosts = {h for h in [_host_of(target), *(extra_hosts or [])] if h}
        return cls(
            target=target,
            operator=operator or "unknown",
            asserted_at=datetime.now(timezone.utc),
            allowed_hosts=frozenset(hosts),
        )

    def permits_host(self, url_or_host: str) -> bool:
        host = _host_of(url_or_host) or url_or_host
        # An empty allowlist means the target is a local path or repo, not a live
        # host — network probing has nothing legitimate to reach, so deny all.
        if not self.allowed_hosts:
            return False
        return host in self.allowed_hosts

    def as_header(self) -> dict:
        return {
            "target": self.target,
            "operator": self.operator,
            "authorized_at": self.asserted_at.isoformat(),
            "scope": sorted(self.allowed_hosts) or ["(no live host — code target)"],
        }


def _host_of(url_or_host: str) -> str:
    if not url_or_host:
        return ""
    if "://" not in url_or_host:
        # Might be a bare host, or a local path / repo — only treat it as a host
        # if it looks like one.
        candidate = url_or_host.split("/")[0]
        return candidate if ("." in candidate or ":" in candidate) and " " not in candidate else ""
    netloc = urlsplit(url_or_host).netloc
    return netloc.split("@")[-1]  # drop any user:pass@
