#!/usr/bin/env python3
"""SubZer0 NG Community terminal verification.

Drives the real Community page with local Chromium:
  - exact ANSI-Shadow banner preserved
  - command typing is staged (output hidden until typing completes)
  - info output renders the expected identity lines
  - Telegram CTA links carry the correct destinations (no network access)
  - responsive terminal at mobile and desktop widths, no horizontal overflow
  - no console/page errors under reduced motion
"""
from __future__ import annotations

import json
import os
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from playwright.sync_api import Page, sync_playwright

ROOT = Path(__file__).resolve().parent
SCREENSHOTS = Path(os.environ.get("SUBZERO_COMMUNITY_SCREENSHOT_DIR", "/tmp/subzero-community-ng-qa"))
RESULT_PATH = Path(os.environ.get("SUBZERO_COMMUNITY_RESULT_PATH", "/tmp/subzero-community-ng-results.json"))
EXPECTED_BANNER_HEAD = "███████╗██╗   ██╗██████╗ ███████╗███████╗██████╗  ██████╗"
EXPECTED_BANNER_ROWS = 6
SCREENSHOTS.mkdir(parents=True, exist_ok=True)


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        pass


def serve(directory: Path) -> ThreadingHTTPServer:
    handler = partial(QuietHandler, directory=str(directory))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def watch_errors(page: Page, errors: list[str]) -> None:
    page.on("pageerror", lambda error: errors.append(f"pageerror: {error}"))
    page.on("console", lambda m: errors.append(f"console: {m.text}") if m.type == "error" else None)


def assert_no_errors(errors: list[str]) -> None:
    assert not errors, "Browser errors: " + "; ".join(errors)


def banner_check(page: Page) -> dict[str, Any]:
    text = page.locator(".term-banner").inner_text()
    lines = [line for line in text.splitlines() if line.strip()]
    assert len(lines) == EXPECTED_BANNER_ROWS, f"banner rows {len(lines)} != {EXPECTED_BANNER_ROWS}"
    assert lines[0].rstrip() == EXPECTED_BANNER_HEAD.rstrip(), "banner first row drifted from ANSI Shadow"
    font = page.evaluate("getComputedStyle(document.querySelector('.term-banner')).fontSize")
    return {"rows": len(lines), "font_size": font}


def check_viewport(browser, url: str, width: int, height: int, results: list) -> None:
    errors: list[str] = []
    page = browser.new_page(viewport={"width": width, "height": height}, device_scale_factor=1)
    watch_errors(page, errors)
    page.emulate_media(reduced_motion="reduce")
    page.goto(f"{url}/?page=community", wait_until="domcontentloaded")
    page.wait_for_function("() => document.querySelector('#term-out') && !document.querySelector('#term-out').hidden", timeout=15_000)
    metrics = banner_check(page)
    overflow = page.evaluate("document.documentElement.scrollWidth > document.documentElement.clientWidth")
    assert not overflow, f"horizontal overflow at {width}x{height}"
    page.screenshot(path=str(SCREENSHOTS / f"community-{width}x{height}.png"), animations="disabled")
    assert_no_errors(errors)
    results.append({"viewport": [width, height], "horizontal_overflow": False, "banner": metrics})
    page.close()


def check_community(browser, url: str) -> dict[str, Any]:
    results: dict[str, Any] = {}
    errors: list[str] = []
    page = browser.new_page(viewport={"width": 1280, "height": 900}, device_scale_factor=1)
    watch_errors(page, errors)
    page.goto(f"{url}/?page=community", wait_until="domcontentloaded")

    # typing is staged: typed command grows, output stays hidden until complete
    page.wait_for_function("() => document.querySelector('#typed') && document.querySelector('#typed').textContent.length > 0", timeout=15_000)
    assert page.locator("#term-out").is_hidden(), "info output appeared before typing finished"
    page.wait_for_function("() => !document.querySelector('#term-out').hidden", timeout=15_000)
    out_text = page.locator("#term-out").inner_text()
    assert "RootAccessClub" in out_text, "identity output missing @RootAccessClub"
    assert "ONLINE" in out_text, "status line missing"
    results["typing"] = {"staged": True, "output_revealed": True}

    results["banner"] = banner_check(page)

    # Telegram CTAs: correct destinations, open safely, no real network in tests
    for handle, expected in (('.term-actions a[href*="RootAccessClub"]', "https://t.me/RootAccessClub"),
                             ('.term-actions a[href*="BugCod3"]', "https://t.me/BugCod3")):
        link = page.locator(handle)
        assert link.count() == 1, f"missing CTA {expected}"
        href = link.get_attribute("href")
        assert href == expected, f"CTA href {href!r} != {expected!r}"
        assert link.get_attribute("target") == "_blank" and "noopener" in (link.get_attribute("rel") or "")
    results["telegram_ctas"] = "verified locally, no network contacted"

    page.screenshot(path=str(SCREENSHOTS / "community-1280x900.png"), animations="disabled")
    assert_no_errors(errors)
    page.close()
    return results


def main() -> None:
    server = serve(ROOT)
    url = f"http://127.0.0.1:{server.server_port}"
    results: dict[str, Any] = {"scope": {"preview": str(ROOT), "telegram_interception": "links verified locally; no Telegram service is contacted."}}
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
            results["community"] = check_community(browser, url)
            layouts = []
            for width, height in ((320, 640), (390, 844), (768, 960), (1440, 1000)):
                check_viewport(browser, url, width, height, layouts)
            results["responsive_layouts"] = layouts
            browser.close()
        result_path = RESULT_PATH
        result_path.parent.mkdir(parents=True, exist_ok=True)
        result_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(results, indent=2))
        print("PASS: NG community verification written to " + str(result_path))
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
