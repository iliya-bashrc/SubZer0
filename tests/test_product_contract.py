#!/usr/bin/env python3
"""Product contract tests: canonical page order, branding, runtime dependencies.

These guard the invariants behind the interaction layer:
  - one canonical page order shared by nav/swipe/keyboard/history
  - every page in the DOM is reachable through that order
  - community.js is loaded by index.html (no dead feature code)
  - no "v2" branding anywhere user-facing
  - Telegram community flow stays the only community CTA set
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ProductContractTests(unittest.TestCase):
    def setUp(self):
        self.index = (ROOT / "index.html").read_text(encoding="utf-8")
        self.app = (ROOT / "app.js").read_text(encoding="utf-8")
        self.community = (ROOT / "community.js").read_text(encoding="utf-8")

    def test_title_is_plain_subzer0(self):
        title = re.search(r"<title>(.*?)</title>", self.index, re.S).group(1)
        self.assertIn("SubZer0", title)
        self.assertNotIn("v2", title.lower())

    def test_no_v2_branding_in_user_facing_files(self):
        for name in ("index.html", "app.js", "community.js", "styles.css"):
            text = (ROOT / name).read_text(encoding="utf-8")
            self.assertNotRegex(text, r"SubZer0\s*v2|Zero-Day Radar v2", f"{name} contains v2 branding")

    def test_canonical_page_order_covers_every_dom_page(self):
        dom_pages = {m for m in re.findall(r'id="page-([a-z-]+)"', self.index) if not m.startswith(("indicator", "size", "prev", "next"))}
        declared = re.search(r"CANONICAL_PAGES\s*=\s*Object\.freeze\(\[([^\]]+)\]\)", self.app)
        self.assertIsNotNone(declared, "app.js must declare CANONICAL_PAGES as the single page-order source")
        order = set(re.findall(r"'([a-z]+)'", declared.group(1)))
        self.assertEqual(dom_pages, order, f"DOM pages {sorted(dom_pages)} != canonical order {sorted(order)}")

    def test_swipe_navigation_is_bound(self):
        self.assertIn("bindSwipeNavigation", self.app)

    def test_community_js_is_loaded(self):
        self.assertRegex(self.index, r'src="community\.js"')

    def test_community_flow_uses_visual_simulation_only(self):
        # xdg-open is displayed as terminal theater; navigation is location-based, never exec
        self.assertIn("xdg-open", self.community)
        self.assertNotRegex(self.community, r"child_process|exec\(|execSync|spawn\(")
        self.assertIn("https://www.t.me/BugCod3", self.community)
        self.assertIn("https://www.t.me/RootAccessClub", self.community)

    def test_community_has_no_github_cta(self):
        community_section = self.index.split('id="page-community"', 1)[-1]
        self.assertNotIn("github.com/iliya-bashrc/SubZer0", community_section)

    def test_every_page_has_one_nav_entry_and_palette_command(self):
        pages = [m for m in re.findall(r'id="page-([a-z-]+)"', self.index) if not m.startswith(("indicator", "size", "prev", "next"))]
        tabs = re.findall(r'id="tab-([a-z-]+)"', self.index)
        self.assertEqual(sorted(pages), sorted(tabs), "every page needs exactly one nav tab")
        for page in pages:
            with self.subTest(page=page):
                self.assertIn(f"page: '{page}'", self.app, f"page {page} has no palette command entry")

    def test_single_canonical_page_order_source(self):
        # No page-order array may be re-declared anywhere else: navigation state has ONE source.
        redeclarations = re.findall(r"(?:pageOrder|pageOrderForKeys)\s*=\s*\[", self.app)
        self.assertEqual(redeclarations, [], "page order must only come from CANONICAL_PAGES")

    def test_kev_watch_reads_only_the_verified_index(self):
        # KEV Watch must reuse the manifest/hash verification path, never a raw fetch.
        self.assertIn("validateKevIndex", self.app)
        self.assertIn("candidate.search_index", self.app)
        self.assertRegex(self.app, r"fetchVerifiedJson\(candidate\.search_index")
        self.assertNotIn("fetch('snapshot/data/search_index.json')", self.app)

    def test_metallic_tokens_are_pinned_by_the_pages_suite(self):
        styles = (ROOT / "styles.css").read_text(encoding="utf-8")
        self.assertIn("--steel-bright: #64747b;", styles)
        self.assertIn("--steel-edge: #3b4a51;", styles)


if __name__ == "__main__":
    unittest.main()
