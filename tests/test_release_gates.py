import hashlib
import re
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "index.html").read_text(encoding="utf-8")
APP = (ROOT / "app.js").read_text(encoding="utf-8")
COMMUNITY = (ROOT / "community.js").read_text(encoding="utf-8")
COMMUNITY_CSS = (ROOT / "community.css").read_text(encoding="utf-8")
UPDATE_WORKFLOW = (ROOT / ".github" / "workflows" / "update.yml").read_text(encoding="utf-8")


class ReleaseGateTests(unittest.TestCase):
    def test_community_ansi_shadow_banner_matches_the_approved_preview(self):
        match = re.search(r'<pre\b[^>]*aria-label="SubZer0 rendered in ANSI Shadow"[^>]*>(.*?)</pre>', HTML, re.S)
        self.assertIsNotNone(match)
        digest = hashlib.sha256(match.group(1).encode("utf-8")).hexdigest()
        self.assertEqual(digest, "20bc80fd1af80dcd1b78728cd698759ce274d36899bc8adcdc80d5a187b1db70")

    def test_named_pages_use_aria_tabs_and_persisted_routes(self):
        for page in ("overview", "center", "community"):
            self.assertIn(f'id="tab-{page}"', HTML)
            self.assertIn(f'id="page-{page}"', HTML)
            self.assertIn(f'data-page="{page}"', HTML)
        self.assertIn('role="tablist"', HTML)
        self.assertIn('role="tabpanel"', HTML)
        self.assertIn("window.addEventListener('popstate'", APP)
        self.assertIn("params.set('page', page)", APP)
        self.assertIn("new CustomEvent('subzero:pagechange'", APP)

    def test_skip_link_precedes_header_and_targets_main(self):
        skip = HTML.index('id="skip-link"')
        header = HTML.index("<header class=\"topbar\">")
        self.assertLess(skip, header)
        self.assertIn('href="#main-content"', HTML[skip:header])
        self.assertIn('<main id="main-content" tabindex="-1">', HTML)

    def test_detail_dialog_has_real_label_target_updated_for_each_record(self):
        self.assertIn('aria-labelledby="detail-title"', HTML)
        self.assertIn('id="detail-title"', HTML)
        self.assertIn("$('detail-title').textContent", APP)

    def test_shards_verify_hash_count_and_daily_totals_before_storage(self):
        for marker in ("crypto.subtle.digest('SHA-256'", "summary.sha256", "payload.length !== Number(summary.count)", "validateUniqueShards(loadedByDay)", "Declared row count mismatch", "SHA-256 mismatch"):
            self.assertIn(marker, APP)
        self.assertIn("classList.add('error')", APP)
        self.assertIn("Retry the full selected date range", APP)

    def test_filters_do_not_publish_partial_results_or_counts(self):
        self.assertIn("function requiresCompleteRange()", APP)
        self.assertIn("const waitingForCompleteRange = needsCompleteRange && !completeRange", APP)
        self.assertIn("const total = waitingForCompleteRange ? null : matches.length", APP)
        self.assertIn("loadAllSelectedDays(rangeGeneration)", APP)
        self.assertIn("$('severity-filters').addEventListener('click'", APP)
        self.assertIn("loadForFilters();", APP)

    def test_free_text_and_public_filters_are_in_stateful_links(self):
        start = APP.index("function makeStateParams(")
        end = APP.index("function writeUrlState(", start)
        serializer = APP[start:end]
        self.assertIn("params.set('q', state.query.trim()", serializer)
        self.assertIn("params.set('severity'", serializer)
        self.assertIn("params.set('vendor'", serializer)
        self.assertIn("params.set('product'", serializer)
        self.assertIn("params.set('cve', pendingCveId)", serializer)
        self.assertIn("state.query = String(params.get('q')", APP)
        self.assertIn("history.pushState", APP)
        self.assertIn("history.replaceState", APP)

    def test_stale_epss_is_disclosed_and_never_used_in_priority(self):
        self.assertIn("function epssIsCurrent()", APP)
        self.assertIn("status.ok === true", APP)
        self.assertIn("age <= 36 * 60 * 60_000", APP)
        self.assertRegex(APP, re.compile(r"if\s*\(epss\s*&&\s*epssIsCurrent\(\)\)\s*components\.push"))
        self.assertIn("STALE/UNVERIFIED; not used in priority", APP)
        self.assertIn("epss-stale", APP)
        self.assertIn("STALE ·", APP)

    def test_community_actions_are_fixed_navigation_not_shell_execution(self):
        self.assertIn("https://www.t.me/BugCod3", COMMUNITY)
        self.assertIn("https://www.t.me/RootAccessClub", COMMUNITY)
        self.assertIn("window.location.assign(channel.url)", COMMUNITY)
        self.assertIn("button.disabled", COMMUNITY)
        self.assertIn("./info", COMMUNITY)
        self.assertNotIn("eval(", COMMUNITY)
        self.assertNotIn("child_process", COMMUNITY)
        self.assertIn('aria-live="polite"', HTML)
        self.assertIn('aria-label="SubZer0 rendered in ANSI Shadow"', HTML)
        self.assertIn("prefers-reduced-motion: reduce", COMMUNITY_CSS)
        self.assertIn("var(--footer-height, 104px)", COMMUNITY_CSS)

    def test_scheduled_refresh_runs_prepublication_gates_and_public_smoke(self):
        integrity = UPDATE_WORKFLOW.index("python scripts/verify_data_snapshot.py")
        browser = UPDATE_WORKFLOW.index("python -m unittest discover -s tests -p 'test_browser_regression.py' -v")
        publish = UPDATE_WORKFLOW.index("Publish changed snapshot to the Pages source branch")
        public = UPDATE_WORKFLOW.index("python scripts/verify_pages.py")
        self.assertLess(integrity, browser)
        self.assertLess(browser, publish)
        self.assertLess(publish, public)
        self.assertNotIn("continue-on-error: true", UPDATE_WORKFLOW)
        self.assertIn("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", UPDATE_WORKFLOW)
        self.assertIn("actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97", UPDATE_WORKFLOW)


if __name__ == "__main__":
    unittest.main()
