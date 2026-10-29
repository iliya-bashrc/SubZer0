from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check_budgets  # noqa: E402
import speed_check  # noqa: E402


def fake_site(root: Path, js: bytes) -> Path:
    for rel, data in {"app.js": js, "app.css": b"a{}", "index.html": b"<!doctype html>", "sw.js": b"",
                      "snapshot/manifest.json": b"{}", "brief/briefing.json": b"{}",
                      "fonts/Inter.woff2": b"x" * 100, "fonts/ChakraPetch-700.woff2": b"x" * 100}.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return root


class BudgetTests(unittest.TestCase):
    def test_small_site_passes(self):
        with tempfile.TemporaryDirectory() as d:
            rows, errors = check_budgets.check(fake_site(Path(d), b"console.log(1)"))
            self.assertEqual(errors, [])
            self.assertTrue(all(ok for *_, ok in rows))

    def test_bloated_app_js_fails(self):
        import os
        with tempfile.TemporaryDirectory() as d:
            _, errors = check_budgets.check(fake_site(Path(d), os.urandom(80 * 1024)))
            self.assertTrue(any(e.startswith("app.js") for e in errors))

    def test_missing_briefing_fails(self):
        with tempfile.TemporaryDirectory() as d:
            site = fake_site(Path(d), b"1")
            (site / "brief" / "briefing.json").unlink()
            _, errors = check_budgets.check(site)
            self.assertIn("brief/briefing.json is missing", errors)

    def test_local_server_gzips_and_stays_inside_the_site(self):
        import gzip
        import urllib.error
        import urllib.request
        with tempfile.TemporaryDirectory() as d:
            site = fake_site(Path(d), b"console.log('hi')")
            srv, port = speed_check.serve(site)
            try:
                r = urllib.request.urlopen(f"http://127.0.0.1:{port}/SubZer0/app.js")
                self.assertEqual(r.headers["Content-Encoding"], "gzip")
                self.assertEqual(gzip.decompress(r.read()), b"console.log('hi')")
                with self.assertRaises(urllib.error.HTTPError):
                    urllib.request.urlopen(f"http://127.0.0.1:{port}/SubZer0/../../etc/passwd")
            finally:
                srv.shutdown()

    def test_checks_workflow_runs_both_gates(self):
        wf = (ROOT / ".github" / "workflows" / "checks.yml").read_text(encoding="utf-8")
        self.assertIn("scripts/check_budgets.py", wf)
        self.assertIn("scripts/speed_check.py", wf)
        self.assertNotIn("npm", wf)
        self.assertNotIn("playwright", wf.lower())


if __name__ == "__main__":
    unittest.main()
