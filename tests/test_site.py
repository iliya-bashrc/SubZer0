import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "index.html").read_text(encoding="utf-8")
CSS = (ROOT / "styles.css").read_text(encoding="utf-8")
JS = (ROOT / "app.js").read_text(encoding="utf-8")


class StaticSiteTests(unittest.TestCase):
    def test_accessible_dashboard_controls_and_detail_dialog_exist(self):
        for element_id in (
            "search-input", "date-from", "date-to", "apply-dates", "severity-filters",
            "sort-select", "load-more", "detail-dialog", "detail-content", "feed-status",
        ):
            with self.subTest(element_id=element_id):
                self.assertIn(f'id="{element_id}"', HTML)
        self.assertIn('aria-live="polite"', HTML)
        self.assertIn('aria-label="Search and filter CVEs"', HTML)

    def test_required_attribution_and_unverified_poc_label_are_visible(self):
        self.assertIn('href="https://t.me/RootAccessClub"', HTML)
        self.assertIn('RootAccessClub', HTML)
        self.assertIn('UNVERIFIED', HTML + JS)
        self.assertIn('NOT PUSH', HTML)
        self.assertIn('NVD API but is not endorsed or certified by the NVD', HTML)

    def test_responsive_layout_and_reduced_motion_are_present(self):
        self.assertIn('@media(max-width:560px)', CSS)
        self.assertIn('@media(max-width:360px)', CSS)
        self.assertIn('@media(prefers-reduced-motion:reduce)', CSS)
        self.assertIn('grid-template-columns:1fr', CSS)

    def test_no_external_frontend_runtime_and_modest_poll_interval(self):
        self.assertIn('const POLL_MS = 120_000', JS)
        self.assertIn('data/manifest.json', JS)
        self.assertNotIn('services.nvd.nist.gov', JS)
        self.assertNotIn('cdn.jsdelivr.net', HTML + JS)
        self.assertNotIn('fonts.googleapis.com', HTML + CSS)

    def test_source_specific_activity_date_basis_is_visible_and_used(self):
        self.assertIn('ACTIVITY DATE · UTC', HTML)
        self.assertIn('GitHub advisory publication', JS)
        self.assertIn('CISA KEV date added', JS)
        self.assertIn('activity_at', JS)

    def test_poc_search_is_constructed_only_from_validated_cve_id(self):
        self.assertIn('^CVE-\\d{4,}-\\d+$', JS)
        self.assertIn('GitHub PoC search', JS)
        self.assertIn('unverified', (HTML + JS).lower())


if __name__ == "__main__":
    unittest.main()
