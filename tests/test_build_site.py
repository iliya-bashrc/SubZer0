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
            self.assertEqual((out / "404.html").read_bytes(), (out / "index.html").read_bytes())
            self.assertTrue((out / ".nojekyll").exists())
            self.assertTrue((out / "snapshot" / "manifest.json").is_file())
            latest = json.loads((out / "api" / "latest.json").read_text(encoding="utf-8"))
            self.assertIn("patch_now", latest)
            self.assertTrue((out / "feed.xml").read_text(encoding="utf-8").startswith("<?xml"))


if __name__ == "__main__":
    unittest.main()
