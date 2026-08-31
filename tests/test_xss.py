"""DOM/reflected XSS tool — confirmation via a fired dialog (script executed).

A fake browser stands in for Chromium: it 'executes' the payload by returning a
dialog echoing the token, so the tool's logic is tested without the real browser.
"""
from __future__ import annotations

import re
from urllib.parse import unquote_plus

from proofmark.tools.xss_tool import XssTool

URL = "https://app.test/search?q=hello&page=1"


class VulnBrowser:
    """Executes any alert('token') payload it is navigated to."""
    def navigate(self, url, **kw):
        m = re.search(r"alert\('([^']+)'\)", unquote_plus(url))
        if m:
            return {"final_url": url, "dialogs": [{"type": "alert", "message": m.group(1)}],
                    "console": [], "text": ""}
        return {"final_url": url, "dialogs": [], "console": [], "text": "safe"}


class EscapedBrowser:
    """Reflects the payload but escapes it — nothing executes, no dialog."""
    def navigate(self, url, **kw):
        return {"final_url": url, "dialogs": [], "console": [], "text": "&lt;script&gt;…"}


class UnavailableBrowser:
    def navigate(self, url, **kw):
        return {"error": "browser unavailable: image not built"}


def test_xss_confirmed_via_dialog():
    out = XssTool(VulnBrowser()).run(url=URL, param="q")
    assert "XSS CONFIRMED" in out.output
    assert "executed in the browser" in out.output


def test_escaped_value_not_flagged():
    out = XssTool(EscapedBrowser()).run(url=URL, param="q")
    assert "No XSS confirmed" in out.output


def test_missing_param_errors():
    out = XssTool(VulnBrowser()).run(url=URL, param="nope")
    assert out.is_error and "was not found" in out.output


def test_browser_unavailable_is_reported():
    out = XssTool(UnavailableBrowser()).run(url=URL, param="q")
    assert out.is_error and "Browser unavailable" in out.output


def test_output_is_fenced_as_untrusted():
    assert XssTool(VulnBrowser()).returns_untrusted_data is True
