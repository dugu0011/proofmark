"""SPA/JS-aware recon — mine API endpoints out of JavaScript bundles."""
from __future__ import annotations

from proofmark.http_client import Request
from proofmark.recon import extract_js_endpoints, run_recon, summarize

BASE = "https://app.test/"


def test_extract_from_fetch_and_axios_calls():
    js = 'fetch("/api/users"); axios.get("/rest/products"); this.http.post("/api/login", body)'
    eps = extract_js_endpoints(js, BASE)
    assert "https://app.test/api/users" in eps
    assert "https://app.test/rest/products" in eps
    assert "https://app.test/api/login" in eps


def test_extract_api_path_literals():
    js = 'const routes = {me: "/api/me", orders: "/api/orders/123"}'
    eps = extract_js_endpoints(js, BASE)
    assert "https://app.test/api/me" in eps
    assert "https://app.test/api/orders/123" in eps


def test_absolute_same_host_kept_cross_host_dropped():
    js = 'fetch("https://app.test/api/keep"); axios.get("https://cdn.other/api/drop")'
    eps = extract_js_endpoints(js, BASE)
    assert "https://app.test/api/keep" in eps
    assert not any("cdn.other" in e for e in eps)


def test_static_assets_dropped():
    js = 'load("/static/main.js"); load("/img/logo.png"); fetch("/api/real")'
    eps = extract_js_endpoints(js, BASE)
    assert eps == {"https://app.test/api/real"}


class FakeClient:
    """Serves a static SPA: one HTML page referencing a JS bundle full of endpoints."""
    def __init__(self, pages):
        self.pages = pages

    def raw(self, request: Request):
        body = self.pages.get(request.url)
        if body is None:
            return {"status": 404, "body": ""}
        return {"status": 200, "body": body}


def test_run_recon_mines_endpoints_from_the_bundle():
    pages = {
        "https://app.test/": '<html><body><h1>News</h1>'
                             '<script src="/bundle.js"></script></body></html>',
        "https://app.test/bundle.js": 'fetch("/api/session"); axios.post("/rest/login");'
                                      'const u="/api/users/me";',
    }
    surface = run_recon(FakeClient(pages), BASE, probe_paths=False)
    assert surface.forms == []                       # the SPA has no HTML forms...
    assert "https://app.test/api/session" in surface.endpoints   # ...but recon still found the API
    assert "https://app.test/rest/login" in surface.endpoints
    assert "https://app.test/api/users/me" in surface.endpoints
    assert "API endpoints mined from JavaScript" in summarize(surface)
