from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_site  # noqa: E402


class PriorityMirrorTests(unittest.TestCase):
    def test_python_priority_matches_the_rules_in_app_js(self):
        poc = {"poc": {"CVE-2026-0002"}, "intel": {}}
        row = lambda i, score, kev, epss: [i, "t", "high", score, kev, epss, "2026-10-01", "2026-10-01", ""]
        self.assertEqual(build_site.priority(row("CVE-2026-0001", 0, 1, None), poc), 1)
        self.assertEqual(build_site.priority(row("CVE-2026-0002", 5.0, 0, 0.2), poc), 1)
        self.assertEqual(build_site.priority(row("CVE-2026-0003", 9.1, 0, 0.0), poc), 2)
        self.assertEqual(build_site.priority(row("CVE-2026-0004", 7.5, 0, 0.06), poc), 2)
        self.assertEqual(build_site.priority(row("CVE-2026-0005", 7.5, 0, 0.0), poc), 3)
        self.assertEqual(build_site.priority(row("CVE-2026-0006", 4.0, 0, None), poc), 4)
        app = (ROOT / "site" / "app.js").read_text(encoding="utf-8")
        for rule in (
            "if(r.k) return [1",
            "if(r.v==='active') return [1",
            "if(r.w&&(r.c>=7||e>=.1)) return [1",
            "if(r.x&&e>=.1) return [1",
            "if(r.c>=9||(r.c>=7&&(r.x||e>=.05))||r.w||r.au) return [2",
            "if(r.c>=7) return [3",
        ):
            self.assertIn(rule, app)


class ShellPolicyTests(unittest.TestCase):
    def test_shell_ships_a_strict_csp_and_no_inline_script_or_handlers(self):
        html = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
        self.assertIn("script-src 'self'", html)
        self.assertIn("connect-src 'self' https://api.first.org", html)
        self.assertNotRegex(html, r"<script(?![^>]*\bsrc=)[^>]*>")
        for name in ("index.html", "app.js"):
            text = (ROOT / "site" / name).read_text(encoding="utf-8")
            self.assertIsNone(re.search(r"\son[a-z]+=\"", text), name)

    def test_build_writes_spa_fallback_feeds_and_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "_site"
            build_site.build(ROOT / "site", ROOT / "public" / "snapshot", out)
            not_found = (out / "404.html").read_text(encoding="utf-8")
            self.assertIn('<meta name="robots" content="noindex">', not_found)
            self.assertIn('src="app.js"', not_found)
            self.assertTrue((out / ".nojekyll").exists())
            self.assertTrue((out / "snapshot" / "manifest.json").is_file())
            latest = json.loads((out / "api" / "latest.json").read_text(encoding="utf-8"))
            self.assertIn("patch_now", latest)
            self.assertTrue((out / "feed.xml").read_text(encoding="utf-8").startswith("<?xml"))

    def test_build_writes_crawlable_pages_and_sitemap(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "_site"
            build_site.build(ROOT / "site", ROOT / "public" / "snapshot", out)
            home = (out / "index.html").read_text(encoding="utf-8")
            self.assertIn(f'<link rel="canonical" href="{build_site.SITE_URL}">', home)
            self.assertIn('"@type":"WebSite"', home)
            pages = sorted((out / "cve").glob("CVE-*.html"))
            self.assertTrue(pages)
            cid = pages[0].stem
            doc = pages[0].read_text(encoding="utf-8")
            self.assertIn(f'<link rel="canonical" href="{build_site.SITE_URL}cve/{cid}">', doc)
            self.assertIn(f"<h1 class=\"credit-name\">{cid}</h1>", doc)
            self.assertIn('src="app.js"', doc)
            self.assertNotRegex(doc, r"<script(?![^>]*\b(src=|type=\"application/ld\+json\"))[^>]*>")
            for slug in ("research", "terminal", "dossier", "about"):
                self.assertTrue((out / f"{slug}.html").is_file(), slug)
            index = (out / "sitemap.xml").read_text(encoding="utf-8")
            self.assertIn("<sitemapindex", index)
            self.assertIn(f"<loc>{build_site.SITE_URL}sitemap-cves.xml</loc>", index)
            cves = (out / "sitemap-cves.xml").read_text(encoding="utf-8")
            self.assertIn(f"<loc>{build_site.SITE_URL}cve/{cid}</loc>", cves)
            self.assertEqual(cves.count("<url>"), len(pages))
            hubs = [p for p in out.glob("*/*.html") if p.parent.name in ("vendor", "product", "week", "weakness")] + [
                out / f"{n}.html" for n in ("vendors", "weekly", "weaknesses")]
            self.assertEqual((out / "sitemap-pages.xml").read_text(encoding="utf-8").count("<url>"), 3 + len(hubs))
            llms = (out / "llms.txt").read_text(encoding="utf-8")
            self.assertTrue(llms.startswith("# SubZer0"))
            self.assertIn(f"{build_site.SITE_URL}api/latest.json", llms)
            self.assertIn("t.me/RootAccessClub", doc)  # Telegram call to action on every CVE page

    def test_hub_pages_are_crawlable_and_routable(self):
        import hub_pages
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "_site"
            build_site.build(ROOT / "site", ROOT / "public" / "snapshot", out)
            sitemap = (out / "sitemap-pages.xml").read_text(encoding="utf-8")
            app = (ROOT / "site" / "app.js").read_text(encoding="utf-8")
            self.assertIn(hub_pages.STATIC_RE.pattern.replace("/", "\\/"), app)  # app and builder agree on hub paths
            for name in ("vendors", "weekly", "weaknesses"):
                doc = (out / f"{name}.html").read_text(encoding="utf-8")
                self.assertIn(f'data-static="{name}"', doc)
                self.assertIn(f"<loc>{build_site.SITE_URL}{name}</loc>", sitemap)
            hubs = json.loads((out / "api" / "hubs.json").read_text(encoding="utf-8"))
            self.assertTrue(hubs["topics"])
            for t in hubs["topics"]:
                self.assertTrue((out / f"{t['path']}.html").is_file(), t["path"])
            self.assertTrue((out / f"{hubs['week']['path']}.html").is_file())
            self.assertLessEqual(len(hubs["week"]["top"]), 5)
            self.assertIn("api/hubs.json", app)
            weeks = sorted((out / "week").glob("*.html"))
            self.assertTrue(weeks)
            weak = sorted((out / "weakness").glob("cwe-*.html"))
            self.assertTrue(weak)
            self.assertEqual({w["path"] for w in hubs["weaknesses"]}, {f"weakness/{p.stem}" for p in weak})
            for page in weeks[:3] + sorted((out / "vendor").glob("*.html"))[:3] + sorted((out / "product").glob("*.html"))[:3] + weak[:3]:
                path = f"{page.parent.name}/{page.stem}"
                self.assertRegex(path, hub_pages.STATIC_RE)
                doc = page.read_text(encoding="utf-8")
                self.assertIn(f'<link rel="canonical" href="{build_site.SITE_URL}{path}">', doc)
                self.assertIn('"@type":"CollectionPage"', doc)
                self.assertIn('class="hub-row', doc)
                if page.parent.name != "week" or "class=\"hub-faq\"" in doc:
                    self.assertIn('"@type":"FAQPage"', doc)
                    self.assertIn('class="hub-faq"', doc)
                self.assertIn(f"<loc>{build_site.SITE_URL}{path}</loc>", sitemap)
                self.assertNotRegex(doc, r"<script(?![^>]*\b(src=|type=\"application/ld\+json\"))[^>]*>")

    def test_hub_grouping(self):
        import hub_pages
        from datetime import date
        mk = lambda n, **kw: {"id": f"CVE-2026-{1000 + n}", "title": kw.get("title", "Bug"), "sev": "high", "score": 7.5, "epss": 0.1, "kev": False,
                              "p": kw.get("p", 3), "why": "", "date": "2026-10-20", "pairs": kw.get("pairs", []), "weap": False, "poc": False}
        items = [mk(i, title="WordPress plugin XSS") for i in range(3)] + [mk(10 + i, pairs=[("Acme Inc.", "Widget")]) for i in range(5)]
        res = hub_pages.build(items, window_start="2026-09-25", today=date(2026, 10, 25))
        paths = {p[0] for p in res["pages"]}
        self.assertIn("product/wordpress", paths)
        self.assertIn("vendor/acme", paths)
        self.assertIn("week/2026-w43", paths)
        self.assertIn(("vendor/acme", "Acme"), res["links"]["CVE-2026-1010"])

    def test_weakness_pages_need_enough_cves(self):
        import hub_pages
        from datetime import date
        mk = lambda n, cwe: {"id": f"CVE-2026-{2000 + n}", "title": "Bug", "sev": "high", "score": 7.5, "epss": 0.2, "kev": n == 0, "p": 1 if n == 0 else 3,
                             "why": "on CISA KEV" if n == 0 else "", "date": "2026-10-20", "pairs": [], "weap": False, "poc": False, "cwe": cwe}
        items = [mk(i, ["CWE-79"]) for i in range(hub_pages.MIN_CWE)] + [mk(50 + i, ["CWE-89"]) for i in range(hub_pages.MIN_CWE - 1)]
        res = hub_pages.build(items, window_start="2026-09-25", today=date(2026, 10, 25), updated="2026-10-25T06:00:00Z")
        pages = {p[0]: p for p in res["pages"]}
        self.assertIn("weakness/cwe-79", pages)
        self.assertNotIn("weakness/cwe-89", pages)
        self.assertIn("weaknesses", pages)
        art, ld = pages["weakness/cwe-79"][3], pages["weakness/cwe-79"][4]
        self.assertIn("How to prevent it", art)
        self.assertIn("Updated <time", art)
        self.assertTrue(any(x.get("@type") == "FAQPage" for x in ld))
        self.assertIn(("weakness/cwe-79", hub_pages.CWE["CWE-79"][0]), res["links"]["CVE-2026-2000"])
        self.assertEqual(hub_pages.summary(res)["weaknesses"][0]["path"], "weakness/cwe-79")


if __name__ == "__main__":
    unittest.main()
