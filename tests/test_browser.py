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


def test_screenshot_is_saved_as_evidence_and_referenced(tmp_path):
    import base64, json
    from proofmark.tools.browser_tool import BrowserTool

    class FakeSandbox:
        runner_path = "/runner.py"
        def exec(self, cmd, timeout=None):
            return 0, json.dumps({
                "final_url": "https://app.test/x", "title": "XSS",
                "text": "ok", "dialogs": [{"type": "alert", "message": "1"}],
                "console": [], "screenshot": base64.b64encode(b"\x89PNGfake").decode(),
            })

    auth = Authorization.grant("https://app.test", "me")
    tool = BrowserTool(auth, artifacts_dir=str(tmp_path))
    tool._sb = FakeSandbox()          # pretend the browser image is up
    tool._runner_path = "/runner.py"

    result = tool.run(url="https://app.test/x")
    assert not result.is_error
    assert "screenshot saved:" in result.output
    assert "DIALOG FIRED" in result.output          # still reports the dialog proof
    assert len(tool.captures) == 1
    saved = tmp_path / tool.captures[0]["file"]
    assert saved.exists() and saved.read_bytes() == b"\x89PNGfake"


def test_screenshot_is_not_written_without_an_artifacts_dir():
    import base64, json
    from proofmark.tools.browser_tool import BrowserTool

    class FakeSandbox:
        runner_path = "/runner.py"
        def exec(self, cmd, timeout=None):
            return 0, json.dumps({"final_url": "u", "title": "t", "text": "",
                                  "dialogs": [], "console": [],
                                  "screenshot": base64.b64encode(b"x").decode()})

    auth = Authorization.grant("https://app.test", "me")
    tool = BrowserTool(auth)          # no artifacts_dir
    tool._sb = FakeSandbox()
    tool._runner_path = "/runner.py"
    result = tool.run(url="https://app.test/x")
    assert not result.is_error
    assert tool.captures == []
    assert "screenshot saved:" not in result.output
