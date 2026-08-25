"""Drive a headless browser for one page interaction, print the result as JSON.

Runs inside the browser sandbox. The point of a real browser is the client-side
class a plain HTTP request cannot reach: reflected/stored/DOM XSS, CSRF flows,
anything that only happens once JavaScript runs. A fired dialog (alert/prompt/
confirm) is the classic, unambiguous proof that injected script executed, so we
capture those specifically.

Usage: python browser_runner.py '<json>'  where json is
  {"url","wait_ms","js","fill":{"selector","value"},"click":"selector"}
"""
import json
import sys

MAX_TEXT = 4000


def main() -> None:
    try:
        spec = json.loads(sys.argv[1])
    except (IndexError, ValueError) as exc:
        print(json.dumps({"error": f"bad spec: {exc}"}))
        return

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(json.dumps({"error": "playwright is not installed in this image"}))
        return

    url = spec.get("url", "")
    dialogs, console = [], []
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            page = browser.new_page()
            # A dialog firing is proof that injected script ran. Record and dismiss.
            page.on("dialog", lambda d: (dialogs.append({"type": d.type, "message": d.message}),
                                         d.dismiss()))
            page.on("console", lambda m: console.append(f"{m.type}: {m.text}"[:200]))

            page.goto(url, timeout=20000, wait_until="load")

            fill = spec.get("fill")
            if isinstance(fill, dict) and fill.get("selector"):
                page.fill(fill["selector"], fill.get("value", ""), timeout=5000)
            if spec.get("click"):
                page.click(spec["click"], timeout=5000)
            if spec.get("js"):
                try:
                    page.evaluate(spec["js"])
                except Exception as exc:  # noqa: BLE001
                    console.append(f"eval-error: {exc}")
            page.wait_for_timeout(int(spec.get("wait_ms", 800)))

            result = {
                "final_url": page.url,
                "title": page.title(),
                "text": page.inner_text("body")[:MAX_TEXT] if page.query_selector("body") else "",
                "dialogs": dialogs,          # non-empty == script executed
                "console": console[-15:],
            }
            browser.close()
            print(json.dumps(result))
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}", "dialogs": dialogs}))


if __name__ == "__main__":
    main()
