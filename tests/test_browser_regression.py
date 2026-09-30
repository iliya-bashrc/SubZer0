"""Optional Playwright regression coverage for real feed interactions.

The regular CI suite remains dependency-free: these tests skip when Playwright or
an installed Chromium executable is not available. To run locally, install
Playwright plus Chromium, then run `python -m unittest tests.test_browser_regression -v`.
"""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
import shutil
import threading
import unittest
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
CHROMIUM = shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
PLAYWRIGHT_AVAILABLE = importlib.util.find_spec("playwright") is not None


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, _format, *_args):
        pass


@unittest.skipUnless(PLAYWRIGHT_AVAILABLE and CHROMIUM, "Playwright and a Chromium executable are optional")
class BrowserRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from playwright.sync_api import sync_playwright

        handler = partial(QuietHandler, directory=str(ROOT))
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}/"
        cls.playwright_manager = sync_playwright()
        cls.playwright = cls.playwright_manager.start()
        cls.browser = cls.playwright.chromium.launch(
            headless=True,
            executable_path=CHROMIUM,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        manifest = json.loads((ROOT / "data" / "manifest.json").read_text(encoding="utf-8"))
        cls.start_date = manifest["window"]["start"][:10]
        cls.end_date = manifest["window"]["end"][:10]

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=2)

    def open_page(self, width, height, mobile=False):
        context = self.browser.new_context(
            viewport={"width": width, "height": height},
            device_scale_factor=2.75 if mobile else 1,
            is_mobile=mobile,
            has_touch=mobile,
            user_agent=(
                "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36"
                if mobile else None
            ),
        )
        page = context.new_page()
        page.goto(self.base_url, wait_until="domcontentloaded", timeout=30000)
        page.wait_for_function(
            "document.querySelector('#loader')?.classList.contains('done')",
            timeout=30000,
        )
        page.wait_for_selector("#feed-list .cve-card", timeout=30000)
        return context, page

    def test_first_record_enters_initial_viewport_across_devices(self):
        for label, width, height, mobile in (
            ("android-320", 320, 740, True),
            ("android-360", 360, 800, True),
            ("android-390", 390, 844, True),
            ("tablet-768", 768, 1024, False),
            ("desktop-1440", 1440, 1000, False),
        ):
            with self.subTest(device=label):
                context, page = self.open_page(width, height, mobile)
                try:
                    first = page.locator("#feed-list .cve-card").first
                    geometry = page.evaluate("""() => {
                      const panel = document.querySelector('#search-panel');
                      const card = document.querySelector('#feed-list .cve-card');
                      const head = card.querySelector('.card-head');
                      return {
                        viewport: [innerWidth, innerHeight],
                        pageWidth: document.documentElement.scrollWidth,
                        panelPosition: getComputedStyle(panel).position,
                        cardTop: card.getBoundingClientRect().top,
                        cardHeadBottom: head.getBoundingClientRect().bottom
                      };
                    }""")
                    self.assertLessEqual(geometry["pageWidth"], width, geometry)
                    self.assertNotEqual(geometry["panelPosition"], "sticky", geometry)
                    self.assertGreater(first.get_attribute("data-cve-id"), "", geometry)
                    self.assertLess(geometry["cardHeadBottom"], height, geometry)
                finally:
                    context.close()

    def test_search_results_are_visible_below_filters_on_desktop_and_android(self):
        for label, width, height, mobile in (
            ("desktop", 1440, 1000, False),
            ("android-390", 390, 844, True),
            ("android-360", 360, 800, True),
            ("android-320", 320, 740, True),
        ):
            with self.subTest(device=label):
                context, page = self.open_page(width, height, mobile)
                try:
                    first_id = page.locator("#feed-list .cve-card").first.get_attribute("data-cve-id")
                    self.assertTrue(first_id)
                    page.locator("#search-input").fill(first_id)
                    page.wait_for_function(
                        "document.querySelector('#feed-status')?.textContent.startsWith('Search covers all')",
                        timeout=30000,
                    )
                    self.assertEqual(page.locator("#feed-count").inner_text(), "1")
                    self.assertEqual(
                        page.locator("#feed-list .cve-card").first.get_attribute("data-cve-id"),
                        first_id,
                    )
                    geometry = page.evaluate("""() => {
                      const panel = document.querySelector('#search-panel');
                      const feed = document.querySelector('#feed');
                      const card = document.querySelector('#feed-list .cve-card');
                      const target = feed.getBoundingClientRect().top + window.scrollY;
                      document.documentElement.style.scrollBehavior = 'auto';
                      window.scrollTo({ top: target, behavior: 'instant' });
                      const p = panel.getBoundingClientRect();
                      const c = card.getBoundingClientRect();
                      const hit = document.elementFromPoint(c.left + Math.min(40, c.width / 2), c.top + Math.min(40, c.height / 2));
                      return {
                        panelPosition: getComputedStyle(panel).position,
                        panelBottom: p.bottom,
                        cardTop: c.top,
                        cardBottom: c.bottom,
                        cardHitTarget: !!hit?.closest('.cve-card'),
                        viewportWidth: document.documentElement.clientWidth,
                        pageWidth: document.documentElement.scrollWidth
                      };
                    }""")
                    self.assertNotEqual(geometry["panelPosition"], "sticky")
                    self.assertTrue(geometry["cardHitTarget"], geometry)
                    self.assertLessEqual(geometry["pageWidth"], geometry["viewportWidth"], geometry)
                finally:
                    context.close()

    def test_clear_search_and_permalink_survive_back_forward(self):
        context, page = self.open_page(390, 844, True)
        try:
            first_id = page.locator("#feed-list .cve-card").first.get_attribute("data-cve-id")
            page.locator("#search-input").fill(first_id)
            page.wait_for_function(
                "document.querySelector('#feed-status')?.textContent.startsWith('Search covers all')",
                timeout=30000,
            )
            page.locator("#search-input").fill("")
            page.wait_for_function(
                "document.querySelector('#search-input').value === '' && "
                "Number(document.querySelector('#feed-count').textContent.replaceAll(',', '')) > 1 && "
                "document.querySelectorAll('#feed-list .cve-card').length > 0",
                timeout=10000,
            )
            self.assertTrue(page.locator("#empty-state").is_hidden())

            permalink = (
                f"{self.base_url}?from={self.start_date}&to={self.end_date}&severity=critical"
            )
            page.goto(permalink, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_function(
                "document.querySelector('#loader')?.classList.contains('done')",
                timeout=30000,
            )
            self.assertEqual(
                page.locator('.severity-filter[aria-pressed="true"]').get_attribute("data-severity"),
                "critical",
            )
            self.assertEqual(page.locator("#date-from").input_value(), self.start_date)
            self.assertEqual(page.locator("#date-to").input_value(), self.end_date)

            page.go_back(wait_until="domcontentloaded", timeout=30000)
            page.wait_for_function(
                "document.querySelector('#loader')?.classList.contains('done')",
                timeout=30000,
            )
            self.assertEqual(urlparse(page.url).query, "")
            page.go_forward(wait_until="domcontentloaded", timeout=30000)
            page.wait_for_function(
                "document.querySelector('#loader')?.classList.contains('done')",
                timeout=30000,
            )
            self.assertEqual(
                page.locator('.severity-filter[aria-pressed="true"]').get_attribute("data-severity"),
                "critical",
            )
            self.assertEqual(urlparse(page.url).query, urlparse(permalink).query)
        finally:
            context.close()

    def test_detail_sheet_and_advanced_filters_remain_touchable(self):
        context, page = self.open_page(390, 844, True)
        try:
            detail = page.locator("#feed-list .cve-card").first.locator('[data-action="detail"]')
            detail.click()
            page.wait_for_function("document.querySelector('#detail-dialog')?.open", timeout=5000)
            self.assertTrue(page.locator("#detail-content").inner_text().strip())
            self.assertLessEqual(
                page.evaluate("document.documentElement.scrollWidth"),
                page.evaluate("document.documentElement.clientWidth"),
            )
            page.keyboard.press("Escape")
            page.wait_for_function("!document.querySelector('#detail-dialog')?.open", timeout=5000)
            self.assertEqual(
                page.evaluate("document.activeElement?.getAttribute('data-action')"),
                "detail",
            )
            page.locator("#advanced-filters > summary").click()
            self.assertTrue(page.locator("#advanced-filters").evaluate("(element) => element.open"))
            self.assertLessEqual(
                page.evaluate("document.documentElement.scrollWidth"),
                page.evaluate("document.documentElement.clientWidth"),
            )
        finally:
            context.close()


if __name__ == "__main__":
    unittest.main()
