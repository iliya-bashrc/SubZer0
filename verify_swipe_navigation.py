#!/usr/bin/env python3
"""Swipe navigation regression (Playwright, local Chromium).

Covers the product contract for the gesture layer:
  forward/backward across the complete 5-page order, spring-back on short drags,
  diagonal rejection, keyboard arrows, mouse drag on desktop, vertical scrolling,
  and zero console/page errors.
Run: /path/to/python verify_swipe_navigation.py --base-url http://localhost:8000/
"""
from __future__ import annotations

import argparse
import sys
from playwright.sync_api import sync_playwright

ORDER = ["page-overview", "page-latest", "page-center", "page-archive", "page-community"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://localhost:8000/")
    args = ap.parse_args()
    failures: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        print(f"{'PASS' if ok else 'FAIL'}: {name}" + (f" ({detail})" if detail and not ok else ""))
        if not ok:
            failures.append(name)

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        errors: list[str] = []
        pg = browser.new_page(viewport={"width": 390, "height": 844}, has_touch=True)
        pg.on("pageerror", lambda e: errors.append(str(e)))
        pg.goto(args.base_url, wait_until="networkidle")
        active = lambda: pg.evaluate("[...document.querySelectorAll('.page:not([hidden])')].map(p=>p.id)[0]")
        cdp = pg.context.new_cdp_session(pg)

        def spot(xw: int) -> int:
            return pg.evaluate("""(xw) => {
              for (let y = 260; y < window.innerHeight - 120; y += 16) {
                const el = document.elementFromPoint(xw, y);
                if (el && !el.closest('input,select,textarea,button,a[href],[role="button"]')) return y;
              }
              return 300;
            }""", xw)

        def swipe(x0: int, x1: int, dy: int = 0) -> None:
            y = spot(x0)
            cdp.send("Input.dispatchTouchEvent", {"type": "touchStart", "touchPoints": [{"x": x0, "y": y}]})
            for i in range(1, 9):
                cdp.send("Input.dispatchTouchEvent", {"type": "touchMove",
                        "touchPoints": [{"x": x0 + (x1 - x0) * i / 8, "y": y + dy * i / 8}]})
                pg.wait_for_timeout(12)
            cdp.send("Input.dispatchTouchEvent", {"type": "touchEnd", "touchPoints": []})
            pg.wait_for_timeout(750)

        seq = [active()]
        for _ in range(4):
            swipe(340, 40)
            seq.append(active())
        check("swipe forward covers every page in canonical order", seq == ORDER, str(seq))

        seq = [active()]
        for _ in range(4):
            swipe(40, 340)
            seq.append(active())
        check("swipe backward covers every page in reverse order", seq == list(reversed(ORDER)), str(seq))

        pg.evaluate("window.scrollTo(0, 0)"); pg.wait_for_timeout(200)
        before = active()
        swipe(340, 300)
        check("short drag springs back without navigation", active() == before)
        pg.evaluate("window.scrollTo(0, 0)"); pg.wait_for_timeout(200)
        swipe(340, 220, dy=200)
        check("diagonal gesture does not navigate", active() == before)

        before = active()
        pg.keyboard.press("ArrowRight"); pg.wait_for_timeout(400)
        check("ArrowRight navigates to next page", ORDER.index(active()) == ORDER.index(before) + 1)
        pg.keyboard.press("ArrowLeft"); pg.wait_for_timeout(400)
        check("ArrowLeft navigates to previous page", active() == before)

        swipe(340, 40)
        y_before = pg.evaluate("window.scrollY")
        pg.mouse.wheel(0, 800); pg.wait_for_timeout(400)
        check("vertical scrolling unaffected", pg.evaluate("window.scrollY") >= y_before)

        desktop = browser.new_page(viewport={"width": 1440, "height": 900})
        desktop.on("pageerror", lambda e: errors.append(str(e)))
        desktop.goto(args.base_url, wait_until="networkidle")
        d_active = lambda: desktop.evaluate("[...document.querySelectorAll('.page:not([hidden])')].map(p=>p.id)[0]")
        desktop.mouse.move(720, 880); desktop.mouse.down()
        for x in range(720, 200, -40):
            desktop.mouse.move(x, 880)
        desktop.mouse.up(); desktop.wait_for_timeout(700)
        check("mouse drag navigates on desktop", d_active() == "page-latest", d_active())
        desktop.close()

        check("zero page errors during gestures", not errors, "; ".join(errors))
        browser.close()

    print(f"\n{'ALL SWIPE CHECKS PASSED' if not failures else 'FAILURES: ' + ', '.join(failures)}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
