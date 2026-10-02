"""Optional Playwright regression coverage for real feed interactions.

The fast CI suite remains dependency-free; a separate browser job installs the
pinned Playwright/Chromium pair. Local runs can use system Chromium or
SUBZERO_CHROMIUM. Install Playwright plus Chromium to run this module locally.
"""
import copy
from datetime import datetime, timedelta
from functools import partial
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import shutil
import threading
import unittest
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
CHROMIUM = os.environ.get("SUBZERO_CHROMIUM") or shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
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
        cls.origin_url = f"http://127.0.0.1:{cls.server.server_port}/"
        cls.base_url = f"{cls.origin_url}?page=center"
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

    def open_page(self, width, height, mobile=False, reduced_motion=None):
        context = self.browser.new_context(
            viewport={"width": width, "height": height},
            device_scale_factor=2.75 if mobile else 1,
            is_mobile=mobile,
            has_touch=mobile,
            reduced_motion=reduced_motion,
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
                    self.assertIsNone(page.locator("#feed-list").get_attribute("aria-live"))
                    if width <= 380:
                        text_sizes = page.evaluate("""() => ({
                          dateLabel: parseFloat(getComputedStyle(document.querySelector('.date-fields > label > span')).fontSize),
                          dateInput: parseFloat(getComputedStyle(document.querySelector('.date-fields input')).fontSize),
                          apply: parseFloat(getComputedStyle(document.querySelector('.apply-button')).fontSize),
                          severity: parseFloat(getComputedStyle(document.querySelector('.severity-filter')).fontSize)
                        })""")
                        for control, size in text_sizes.items():
                            with self.subTest(control=control, width=width):
                                minimum = 10 if control == "dateLabel" else 12
                                self.assertGreaterEqual(size, minimum, text_sizes)
                finally:
                    context.close()

    def test_mobile_center_heading_retains_copy_and_stacked_counters(self):
        context, page = self.open_page(360, 800, True)
        try:
            metrics = page.evaluate("""() => {
              const heading = document.querySelector('.page-center .masthead.center-heading');
              const summary = document.querySelector('.page-center .masthead-summary');
              const totals = document.querySelector('.page-center .center-snapshot-summary');
              const card = document.querySelector('#feed-list .cve-card');
              return {
                columns: getComputedStyle(heading).gridTemplateColumns.trim().split(/\\s+/).length,
                summary: summary.getBoundingClientRect().toJSON(),
                totals: totals.getBoundingClientRect().toJSON(),
                cardTop: card.getBoundingClientRect().top,
                pageWidth: document.documentElement.scrollWidth
              };
            }""")
            self.assertEqual(metrics["columns"], 1, metrics)
            self.assertGreater(metrics["summary"]["height"], 12, metrics)
            self.assertGreaterEqual(metrics["totals"]["top"], metrics["summary"]["bottom"], metrics)
            self.assertLess(metrics["cardTop"], 700, metrics)
            self.assertLessEqual(metrics["pageWidth"], 360, metrics)
        finally:
            context.close()

    def test_mobile_filter_controls_are_readable_and_tappable(self):
        for width, height in ((320, 740), (360, 800), (390, 844)):
            with self.subTest(width=width):
                context, page = self.open_page(width, height, True)
                try:
                    metrics = page.evaluate("""() => {
                      const filters = document.querySelector('.severity-filters');
                      const buttons = [...filters.querySelectorAll('button')];
                      return {
                        columns: getComputedStyle(filters).gridTemplateColumns.trim().split(/\\s+/).length,
                        severityFont: parseFloat(getComputedStyle(buttons[0]).fontSize),
                        dateLabelDisplay: getComputedStyle(document.querySelector('.date-fields > label')).display,
                        dateLabelFont: parseFloat(getComputedStyle(document.querySelector('.date-fields > label > span')).fontSize),
                        dateInputFont: parseFloat(getComputedStyle(document.querySelector('.date-fields input')).fontSize),
                        applyFont: parseFloat(getComputedStyle(document.querySelector('.apply-button')).fontSize),
                        buttonHeights: buttons.map(button => button.getBoundingClientRect().height),
                        firstCardTop: document.querySelector('#feed-list .cve-card').getBoundingClientRect().top,
                        pageWidth: document.documentElement.scrollWidth
                      };
                    }""")
                    self.assertEqual(metrics["columns"], 3, metrics)
                    self.assertGreaterEqual(metrics["severityFont"], 12, metrics)
                    self.assertEqual(metrics["dateLabelDisplay"], "grid", metrics)
                    self.assertGreaterEqual(metrics["dateLabelFont"], 10, metrics)
                    self.assertGreaterEqual(metrics["dateInputFont"], 12 if width <= 380 else 11, metrics)
                    self.assertGreaterEqual(metrics["applyFont"], 12, metrics)
                    self.assertTrue(all(height >= 44 for height in metrics["buttonHeights"]), metrics)
                    self.assertLessEqual(metrics["pageWidth"], width, metrics)
                    if width == 320:
                        self.assertLessEqual(metrics["firstCardTop"], 660, metrics)

                    high = page.locator('.severity-filter[data-severity="high"]')
                    high.tap()
                    self.assertEqual(high.get_attribute("aria-pressed"), "true")
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
                    page.wait_for_function(
                        "new URL(location.href).searchParams.get('q') === document.querySelector('#search-input').value",
                        timeout=10000,
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

    def test_three_routes_restore_tabs_and_community_terminal(self):
        context = self.browser.new_context(viewport={"width": 390, "height": 844}, is_mobile=True, has_touch=True)
        opened = []
        context.route("https://www.t.me/**", lambda route: (opened.append(route.request.url), route.fulfill(status=200, body="OK")))
        page = context.new_page()
        try:
            page.goto(self.origin_url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_function("document.querySelector('#loader')?.classList.contains('done')", timeout=30000)
            page.keyboard.press("Tab")
            self.assertEqual(page.evaluate("document.activeElement?.id"), "skip-link")
            page.keyboard.press("Enter")
            self.assertEqual(page.evaluate("document.activeElement?.id"), "main-content")
            self.assertTrue(page.locator("#page-overview").is_visible())
            self.assertEqual(page.title(), "SubZer0 — Overview")

            page.locator("#tab-center").click()
            page.wait_for_function("new URL(location.href).searchParams.get('page') === 'center'")
            self.assertTrue(page.locator("#page-center").is_visible())
            page.locator("#tab-community").click()
            page.wait_for_function("new URL(location.href).searchParams.get('page') === 'community'")
            page.wait_for_function("!document.querySelector('#terminal-info')?.hidden", timeout=10000)
            self.assertTrue(page.locator("#page-community").is_visible())
            self.assertIn("rendered in ANSI Shadow", page.locator(".terminal-banner").get_attribute("aria-label"))
            self.assertIn("CVE Intelligence & Vulnerability Research", page.locator("#terminal-info").inner_text())
            self.assertIn("@BugCod3", page.locator("#terminal-info").inner_text())
            self.assertIn("@RootAccessClub", page.locator("#terminal-info").inner_text())
            self.assertEqual(page.locator("#action-session").is_visible(), False)
            self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), 390)

            metrics = page.evaluate("({height:innerHeight, documentHeight:document.documentElement.scrollHeight, pageHeight:document.querySelector('#page-community').getBoundingClientRect().height, footerHeight:document.querySelector('.footer').getBoundingClientRect().height})")
            self.assertLessEqual(metrics["documentHeight"], metrics["height"] + 2, metrics)

            page.locator("#join-bugcod3").click()
            page.wait_for_url("https://www.t.me/BugCod3", timeout=5000)
            self.assertEqual(opened[-1], "https://www.t.me/BugCod3")

            page.goto(f"{self.origin_url}?page=community", wait_until="domcontentloaded", timeout=30000)
            page.wait_for_function("document.querySelector('#loader')?.classList.contains('done')", timeout=30000)
            page.wait_for_function("!document.querySelector('#terminal-info')?.hidden", timeout=10000)
            page.locator("#join-rootaccessclub").click()
            page.wait_for_url("https://www.t.me/RootAccessClub", timeout=5000)
            self.assertEqual(opened[-1], "https://www.t.me/RootAccessClub")
        finally:
            context.close()

        reduced = self.browser.new_context(viewport={"width": 390, "height": 844}, reduced_motion="reduce")
        reduced_page = reduced.new_page()
        try:
            reduced_page.goto(f"{self.origin_url}?page=community", wait_until="domcontentloaded", timeout=30000)
            reduced_page.wait_for_function("document.querySelector('#loader')?.classList.contains('done')", timeout=30000)
            reduced_page.wait_for_function("!document.querySelector('#terminal-info')?.hidden", timeout=10000)
            self.assertEqual(reduced_page.locator("#typing-caret").evaluate("element => getComputedStyle(element).animationName"), "none")
        finally:
            reduced.close()

    def test_clear_search_and_permalink_survive_back_forward(self):
        context, page = self.open_page(390, 844, True)
        try:
            first_id = page.locator("#feed-list .cve-card").first.get_attribute("data-cve-id")
            page.locator("#search-input").fill(first_id)
            page.wait_for_function(
                "document.querySelector('#feed-status')?.textContent.startsWith('Search covers all')",
                timeout=30000,
            )
            page.wait_for_function(
                "new URL(location.href).searchParams.get('q') === document.querySelector('#search-input').value",
                timeout=10000,
            )
            page.locator("#search-input").fill("")
            page.wait_for_function(
                "document.querySelector('#search-input').value === '' && "
                "Number(document.querySelector('#feed-count').textContent.replaceAll(',', '')) > 1 && "
                "document.querySelectorAll('#feed-list .cve-card').length > 0",
                timeout=10000,
            )
            page.wait_for_function("!new URL(location.href).searchParams.has('q')", timeout=10000)
            page.go_back(wait_until="domcontentloaded", timeout=30000)
            self.assertEqual(page.locator("#search-input").input_value(), first_id)
            self.assertEqual(page.locator("#feed-count").inner_text(), "1")
            page.go_forward(wait_until="domcontentloaded", timeout=30000)
            self.assertEqual(page.locator("#search-input").input_value(), "")
            self.assertTrue(page.locator("#empty-state").is_hidden())

            permalink = (
                f"{self.origin_url}?from={self.start_date}&to={self.end_date}&severity=critical"
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
            self.assertEqual(urlparse(page.url).query, "page=center")
            page.go_forward(wait_until="domcontentloaded", timeout=30000)
            page.wait_for_function(
                "document.querySelector('#loader')?.classList.contains('done')",
                timeout=30000,
            )
            self.assertEqual(
                page.locator('.severity-filter[aria-pressed="true"]').get_attribute("data-severity"),
                "critical",
            )
            restored = parse_qs(urlparse(page.url).query)
            self.assertEqual(restored.get("page"), ["center"])
            self.assertEqual(restored.get("severity"), ["critical"])
            self.assertEqual(page.locator("#date-from").input_value(), self.start_date)
            self.assertEqual(page.locator("#date-to").input_value(), self.end_date)
        finally:
            context.close()

    def test_integrity_failure_withholds_results_and_retry_recovers(self):
        manifest = json.loads((ROOT / "data" / "manifest.json").read_text(encoding="utf-8"))
        nonempty = [item for item in manifest["days"] if int(item.get("count", 0)) > 0]
        target = nonempty[-3]
        context = self.browser.new_context(viewport={"width": 1280, "height": 900})
        context.add_init_script(f"""(() => {{
          const nativeFetch = window.fetch.bind(window);
          let attempts = 0;
          window.__integrityShardAttempts = () => attempts;
          window.fetch = (input, init) => {{
            const raw = typeof input === 'string' ? input : input.url || String(input);
            const url = new URL(raw, window.location.href);
            if (url.pathname.endsWith('/{target['date']}.json')) {{
              attempts += 1;
              if (attempts === 1) return Promise.resolve(new Response('', {{status:404}}));
              if (attempts === 2) return nativeFetch(input, init).then(async response => {{
                const rows = await response.json();
                rows[0].title = 'TAMPERED INTEGRITY TEST RECORD';
                return new Response(JSON.stringify(rows) + '\\n', {{status:200, headers:{{'Content-Type':'application/json'}}}});
              }});
            }}
            return nativeFetch(input, init);
          }};
        }})();""")
        page = context.new_page()
        try:
            page.goto(self.base_url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_function("document.querySelector('#loader')?.classList.contains('done')", timeout=30000)
            page.wait_for_function("window.__integrityShardAttempts() >= 1", timeout=30000)
            page.wait_for_function(
                "document.querySelector('#feed-status')?.textContent.includes('Some feed data could not be loaded or verified')",
                timeout=30000,
            )
            first_id = page.locator("#feed-list .cve-card").first.get_attribute("data-cve-id")
            page.locator("#search-input").fill(first_id)
            page.wait_for_function("document.querySelector('#feed-status')?.textContent.includes('Some feed data could not be loaded or verified')", timeout=30000)
            page.wait_for_function("document.querySelector('#feed-status')?.textContent.includes('SHA-256 mismatch')", timeout=30000)
            self.assertEqual(page.locator("#feed-count").inner_text(), "—")
            self.assertEqual(page.locator("#feed-list .cve-card").count(), 0)
            self.assertTrue(page.locator("#feed-list").get_attribute("aria-busy") == "true")

            page.locator("#load-more").click()
            page.wait_for_function("document.querySelector('#feed-status')?.textContent.startsWith('Search covers all')", timeout=60000)
            self.assertEqual(page.locator("#feed-count").inner_text(), "1")
            self.assertEqual(page.locator("#feed-list .cve-card").first.get_attribute("data-cve-id"), first_id)
            self.assertEqual(page.evaluate("window.__integrityShardAttempts()"), 3)
        finally:
            context.close()

    def test_direct_cve_url_opens_a_named_detail_dialog(self):
        manifest = json.loads((ROOT / "data" / "manifest.json").read_text(encoding="utf-8"))
        latest = next(item for item in reversed(manifest["days"]) if int(item.get("count", 0)) > 0)
        records = json.loads((ROOT / latest["path"]).read_text(encoding="utf-8"))
        cve_id = records[0]["id"]
        context = self.browser.new_context(viewport={"width": 1280, "height": 900})
        page = context.new_page()
        try:
            page.goto(f"{self.origin_url}?cve={cve_id}", wait_until="domcontentloaded", timeout=30000)
            page.wait_for_function("document.querySelector('#loader')?.classList.contains('done')", timeout=30000)
            page.wait_for_function("document.querySelector('#detail-dialog')?.open", timeout=60000)
            self.assertTrue(page.locator("#detail-title").inner_text().startswith(cve_id))
            self.assertEqual(page.locator("#detail-dialog").get_attribute("aria-labelledby"), "detail-title")
            self.assertEqual(parse_qs(urlparse(page.url).query).get("cve", [""])[0], cve_id)
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

    def test_watchlist_pair_survives_optional_facet_index_failure(self):
        context = self.browser.new_context(viewport={"width": 390, "height": 844}, is_mobile=True, has_touch=True)
        context.add_init_script("""(() => {
          localStorage.setItem('subzero:watchlist', JSON.stringify([{vendor:'npm', product:'serialize-javascript'}]));
          const nativeFetch = window.fetch.bind(window);
          window.fetch = (input, init) => {
            const raw = typeof input === 'string' ? input : input.url || String(input);
            const url = new URL(raw, window.location.href);
            if (url.pathname.endsWith('/data/facets.json')) return Promise.reject(new TypeError('fixture: facets unavailable'));
            return nativeFetch(input, init);
          };
        })();""")
        page = context.new_page()
        try:
            page.goto(self.base_url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_function("document.querySelector('#loader')?.classList.contains('done')", timeout=30000)
            page.locator("#workspace-tools > summary").click()
            page.wait_for_selector("#workspace-tools .watch-filter", timeout=5000)
            page.locator("#workspace-tools .watch-filter").click()
            self.assertEqual(page.locator("#vendor-filter").input_value(), "npm")
            self.assertEqual(page.locator("#product-filter").input_value(), "serialize-javascript")
        finally:
            context.close()

    def test_applying_snapshot_discards_delayed_previous_shard_response(self):
        manifest = json.loads((ROOT / "data" / "manifest.json").read_text(encoding="utf-8"))
        nonempty = [item for item in manifest["days"] if int(item.get("count", 0)) > 0]
        target = nonempty[-3]
        day = target["date"]
        old_version = manifest["generated_at"]
        parsed_version = datetime.fromisoformat(old_version.replace("Z", "+00:00"))
        new_version = (parsed_version + timedelta(seconds=1)).isoformat(timespec="seconds").replace("+00:00", "Z")
        updated_manifest = copy.deepcopy(manifest)
        updated_manifest["generated_at"] = new_version
        updated_manifest_target = next(item for item in updated_manifest["days"] if item["date"] == day)

        old_records = json.loads((ROOT / "data" / f"{day}.json").read_text(encoding="utf-8"))
        record_id = old_records[0]["id"]
        stale_records = copy.deepcopy(old_records)
        fresh_records = copy.deepcopy(old_records)
        stale_record = next(item for item in stale_records if item["id"] == record_id)
        fresh_record = next(item for item in fresh_records if item["id"] == record_id)
        stale_record["title"] = "STALE SNAPSHOT REGRESSION MARKER"
        fresh_record["title"] = "FRESH SNAPSHOT REGRESSION MARKER"
        stale_bytes = (json.dumps(stale_records, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        fresh_bytes = (json.dumps(fresh_records, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        updated_manifest_target["count"] = len(fresh_records)
        updated_manifest_target["sha256"] = hashlib.sha256(fresh_bytes).hexdigest()

        bootstrap = """(() => {
          const nativeFetch = window.fetch.bind(window);
          const oldVersion = __OLD_VERSION__;
          const newVersion = __NEW_VERSION__;
          const shardPath = '/data/__DAY__.json';
          const newManifest = __NEW_MANIFEST__;
          const stalePayload = __STALE_PAYLOAD__;
          const freshPayload = __FRESH_PAYLOAD__;
          let manifestRequests = 0;
          window.fetch = (input, init) => {
            const raw = typeof input === 'string' ? input : input.url || String(input);
            const url = new URL(raw, window.location.href);
            if (url.pathname.endsWith('/data/manifest.json')) {
              manifestRequests += 1;
              if (manifestRequests > 1) return Promise.resolve(new Response(newManifest, {status:200, headers:{'Content-Type':'application/json'}}));
            }
            if (url.pathname.endsWith(shardPath)) {
              const version = url.searchParams.get('v');
              if (version === oldVersion) return new Promise((resolve) => {
                window.__releaseStaleShard = () => {
                  resolve(new Response(stalePayload, {status:200, headers:{'Content-Type':'application/json'}}));
                  window.__staleShardReleased = true;
                };
              });
              if (version === newVersion) return Promise.resolve(new Response(freshPayload, {status:200, headers:{'Content-Type':'application/json'}}));
            }
            return nativeFetch(input, init);
          };
        })();"""
        replacements = {
            "__OLD_VERSION__": json.dumps(old_version),
            "__NEW_VERSION__": json.dumps(new_version),
            "__DAY__": day,
            "__NEW_MANIFEST__": json.dumps(json.dumps(updated_manifest, ensure_ascii=False, separators=(",", ":"))),
            "__STALE_PAYLOAD__": json.dumps(stale_bytes.decode("utf-8")),
            "__FRESH_PAYLOAD__": json.dumps(fresh_bytes.decode("utf-8")),
        }
        for token, value in replacements.items():
            bootstrap = bootstrap.replace(token, value)

        context = self.browser.new_context(viewport={"width": 1280, "height": 900})
        context.add_init_script(bootstrap)
        page = context.new_page()
        try:
            page.goto(self.base_url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_function("document.querySelector('#loader')?.classList.contains('done')", timeout=30000)
            page.locator("#search-input").fill("snapshot regression marker")
            page.wait_for_function("typeof window.__releaseStaleShard === 'function'", timeout=30000)
            page.locator("#refresh-button").click()
            page.wait_for_function("!document.querySelector('#new-notice').hidden", timeout=30000)
            page.locator("#view-new").click()
            page.wait_for_function("document.querySelector('#search-input').value === ''", timeout=5000)
            page.evaluate("window.__releaseStaleShard()")
            page.wait_for_function("window.__staleShardReleased === true", timeout=5000)
            page.wait_for_timeout(150)
            page.locator("#search-input").fill("snapshot regression marker")
            page.wait_for_function(
                "document.querySelector('#feed-status')?.textContent.startsWith('Search covers all')",
                timeout=60000,
            )
            card = page.locator(f'#feed-list .cve-card[data-cve-id="{record_id}"]')
            self.assertEqual(card.count(), 1)
            self.assertIn("FRESH SNAPSHOT REGRESSION MARKER", card.inner_text())
        finally:
            context.close()


if __name__ == "__main__":
    unittest.main()
