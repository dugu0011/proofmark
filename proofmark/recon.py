"""Mapping the attack surface, so the agent tests what exists — not only what
you named.

Two cheap, high-value moves: parse each page for links, forms and their
parameters and follow same-host links a little way (a bounded crawl), and probe
a short list of paths that often exist and often should not be reachable
(.env, .git, admin, debug). Everything goes through the scoped client, so recon
cannot wander off the authorized host.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from proofmark.http_client import HttpClient, Request

# Paths worth a look on almost any web target. Small on purpose — recon should
# hint, not hammer.
COMMON_PATHS = [
    "robots.txt", "sitemap.xml", ".env", ".git/HEAD", ".git/config",
    "api", "api/", "admin", "login", "health", "status", "debug",
    "swagger.json", "openapi.json", ".well-known/security.txt",
]


@dataclass
class Surface:
    pages: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)     # {action, method, inputs[]}
    links: set[str] = field(default_factory=set)
    scripts: set[str] = field(default_factory=set)
    found_paths: list[tuple[str, int]] = field(default_factory=list)  # (url, status)


class _Extract(HTMLParser):
    """Pulls anchors, forms + inputs, and script srcs out of one page."""

    def __init__(self, base: str) -> None:
        super().__init__()
        self.base = base
        self.links: set[str] = set()
        self.scripts: set[str] = set()
        self.forms: list[dict] = []
        self._form: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.add(urljoin(self.base, a["href"]))
        elif tag == "script" and a.get("src"):
            self.scripts.add(urljoin(self.base, a["src"]))
        elif tag == "form":
            self._form = {"action": urljoin(self.base, a.get("action", "")),
                          "method": (a.get("method") or "GET").upper(), "inputs": []}
        elif tag in ("input", "textarea", "select") and self._form is not None:
            if a.get("name"):
                self._form["inputs"].append(a["name"])

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def parse_html(base: str, html: str) -> _Extract:
    p = _Extract(base)
    try:
        p.feed(html)
    except Exception:  # noqa: BLE001 - malformed HTML must not break recon
        pass
    return p


def _same_host(a: str, b: str) -> bool:
    return urlsplit(a).netloc.split("@")[-1] == urlsplit(b).netloc.split("@")[-1]


def run_recon(client: HttpClient, base_url: str, *, max_pages: int = 8,
              probe_paths: bool = True) -> Surface:
    surface = Surface()
    queue = [base_url]
    seen: set[str] = set()

    while queue and len(surface.pages) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        data = client.raw(Request("GET", url))
        if data is None or data.get("status") is None:
            continue
        surface.pages.append(url)
        ex = parse_html(url, data.get("body", ""))
        surface.forms.extend(ex.forms)
        surface.links |= ex.links
        surface.scripts |= ex.scripts
        for link in ex.links:
            if _same_host(link, base_url) and link not in seen:
                queue.append(link)

    if probe_paths:
        root = f"{urlsplit(base_url).scheme}://{urlsplit(base_url).netloc}/"
        for path in COMMON_PATHS:
            data = client.raw(Request("GET", urljoin(root, path)))
            if data and data.get("status") not in (None, 404):
                surface.found_paths.append((urljoin(root, path), data["status"]))

    return surface


def summarize(surface: Surface) -> str:
    lines = [f"Mapped {len(surface.pages)} page(s), {len(surface.links)} link(s), "
             f"{len(surface.forms)} form(s)."]
    if surface.found_paths:
        lines.append("Interesting paths that responded (not 404):")
        for url, status in surface.found_paths:
            lines.append(f"  HTTP {status}  {url}")
    if surface.forms:
        lines.append("Forms (candidate injection points):")
        for f in surface.forms[:15]:
            params = ", ".join(f["inputs"]) or "(no named inputs)"
            lines.append(f"  {f['method']} {f['action']}  params: {params}")
    interesting_links = sorted(l for l in surface.links)[:20]
    if interesting_links:
        lines.append("Links:")
        lines += [f"  {l}" for l in interesting_links]
    return "\n".join(lines)
