#!/usr/bin/env python3
"""SubZer0 NG full-feed browser regression.

Serves the published snapshot locally and drives the real UI with Playwright:
  - Overview renders verified totals from the manifest
  - Explore searches the compact index (15k records) and severity filtering is data-backed
  - CVE detail lazily loads the full record from its shard with labeled references
  - Changes page renders the real change feed
  - URL state survives reload
The snapshot itself is validated separately by verify_data_snapshot.py.
"""
from __future__ import annotations

import argparse
import json
from http.server import SimpleHTTPRequestHandler, HTTPServer
import threading
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parent


def nfmt(n: int) -> str:
    return f"{n:,}"


def serve(root: Path, port: int):
    handler = lambda *a, **kw: SimpleHTTPRequestHandler(*a, directory=str(root), **kw)
    server = HTTPServer(("127.0.0.1", port), handler)
    url = f"http://127.0.0.1:{port}/"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, url


def expect_overview(page, expected_cves: int, url: str) -> None:
    page.goto(url, wait_until="domcontentloaded")
    expect(page.locator("#kpi-total")).to_have_text(nfmt(expected_cves), timeout=30_000)
    expect(page.locator("#kpi-kev")).not_to_have_text("—", timeout=10_000)


def expect_explore_search(page, total: int) -> None:
    print("[step] explore", flush=True)
    page.locator('.nav-btn[data-nav="explore"]').click(force=True)
    expect(page.locator("#explore-count")).to_have_text(nfmt(total), timeout=30_000)
    page.fill("#search", "kernel")
    page.wait_for_function(
        "() => document.querySelector('#results').children.length > 0", timeout=15_000
    )
    page.wait_for_timeout(500)
    assert page.locator("#results .rec").count() > 0, "search returned no records"
    page.fill("#search", "")
    page.wait_for_timeout(400)
    page.locator('[data-sev="high"]').click(force=True)
    page.wait_for_timeout(400)
    high = int(page.locator("#explore-count").inner_text().replace(",", ""))
    assert high > 0, "severity filter produced empty set"


def expect_detail_dossier(page) -> None:
    print("[step] detail", flush=True)
    page.locator("#results .rec").first.click()
    dialog = page.locator("dialog#detail")
    expect(dialog).to_be_visible(timeout=10_000)
    page.wait_for_function(
        "() => !document.querySelector('#d-loading')", timeout=20_000
    )
    assert dialog.locator(".d-refrow a").count() >= 1, "detail dossier has no references"
    page.keyboard.press("Escape")
    expect(dialog).not_to_be_visible(timeout=5_000)


def expect_changes(page) -> None:
    print("[step] changes", flush=True)
    page.locator('.nav-btn[data-nav="changes"]').click(force=True)
    cards = page.locator("#changes-list .rec")
    expect(cards.first).to_be_visible(timeout=20_000)
    assert cards.count() > 0, "changes page rendered no events"
    summary = page.locator("#changes-summary").inner_text()
    assert "events" in summary.lower(), f"unexpected changes summary: {summary!r}"


def expect_url_state(page) -> None:
    print("[step] urlstate", flush=True)
    page.locator('.nav-btn[data-nav="explore"]').click(force=True)
    page.wait_for_timeout(300)
    page.fill("#search", "openssl")
    page.wait_for_timeout(600)
    assert "q=openssl" in page.url, f"search state not in URL: {page.url}"
    page.reload(wait_until="domcontentloaded")
    page.wait_for_timeout(800)
    assert page.locator("#search").input_value() == "openssl", "search state lost on reload"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=str(ROOT / "."), help="site root to serve")
    parser.add_argument("--port", type=int, default=8931)
    parser.add_argument("--headed", action="store_true")
    args = parser.parse_args()

    site_root = Path(args.root).resolve().absolute()
    manifest = json.loads((site_root / "snapshot" / "manifest.json").read_text())
    total = int(manifest["totals"]["cves"])
    assert manifest.get("complete") is True, "refusing UI regression against an incomplete snapshot"

    index_rows = json.loads((site_root / "snapshot" / "data" / "search_index.json").read_text())
    assert len(index_rows) == total, "search index does not match manifest totals"

    server, url = serve(site_root, args.port)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=not args.headed)
            page = browser.new_page(viewport={"width": 1280, "height": 900})

            expect_overview(page, total, url)
            expect_explore_search(page, total)
            expect_detail_dossier(page)
            expect_changes(page)
            expect_url_state(page)

            # mobile pass: search reachable and on-screen
            mobile = browser.new_page(viewport={"width": 390, "height": 844})
            expect_overview(mobile, total, url)
            mobile.locator('.nav-btn[data-nav="explore"]').click(force=True)
            mobile.wait_for_timeout(300)
            mobile.fill("#search", "kernel")
            mobile.wait_for_timeout(700)
            box = mobile.locator("#search").bounding_box()
            assert box and box["y"] >= 0, "mobile search positioned off-screen"

            browser.close()
        print("UI REGRESSION PASSED: overview, explore search, detail dossier, changes, URL state, mobile")
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()
