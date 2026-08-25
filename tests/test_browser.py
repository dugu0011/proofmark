"""The browser tool's guards, without needing the heavy Chromium image.

The scope check and the graceful "not built yet" path must work whether or not
the image exists — those are the parts a run depends on for safety and for a
clear message.
"""
from proofmark.authorization import Authorization
from proofmark.tools.browser_tool import BrowserTool


def test_out_of_scope_is_refused_before_the_browser_starts():
    auth = Authorization.grant("https://app.test", "me")
    tool = BrowserTool(auth)
    result = tool.run(url="https://evil.test/xss")
    assert result.is_error and "outside the authorized scope" in result.output
    # nothing was started
    assert tool._sb is None


def test_missing_image_degrades_gracefully(monkeypatch):
    from proofmark import sandbox as sb_mod

    # Force the sandbox to report the image as not built.
    def boom(self):
        raise sb_mod.SandboxError("image 'proofmark-sandbox:latest' is not built. Run: proofmark build-sandbox")
    monkeypatch.setattr(sb_mod.Sandbox, "start", boom)

    auth = Authorization.grant("https://app.test", "me")
    tool = BrowserTool(auth)
    result = tool.run(url="https://app.test/page")
    assert result.is_error
    assert "build-sandbox" in result.output
    # a second call does not retry-and-crash; it stays unavailable
    assert tool.run(url="https://app.test/page").is_error
