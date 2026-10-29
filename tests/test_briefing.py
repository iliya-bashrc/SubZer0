from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import briefing  # noqa: E402
import build_site  # noqa: E402

SNAPSHOT = ROOT / "public" / "snapshot"


class BriefingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest, cls.rows, cls.ctx = build_site.load_index(SNAPSHOT)
        cls.mbytes = (SNAPSHOT / "manifest.json").read_bytes()
        intel = build_site._read_verified(SNAPSHOT, cls.manifest.get("intel"))
        cls.raw = briefing.build(cls.mbytes, cls.manifest, cls.rows, cls.ctx, intel, build_site.facts, build_site.priority)
        cls.doc = json.loads(cls.raw)

    def test_pins_the_manifest_and_stays_small(self):
        self.assertEqual(self.doc["schema"], 1)
        self.assertEqual(self.doc["manifest_sha256"], hashlib.sha256(self.mbytes).hexdigest())
        self.assertLess(len(self.raw), briefing.MAX_BYTES)
        self.assertLess(len(self.raw), self.manifest["search_index"]["bytes"] / 10)

    def test_rows_are_exact_copies_of_the_verified_index(self):
        full = {r[0]: r for r in self.rows}
        for r in self.doc["rows"]:
            self.assertEqual(r, full[r[0]])
        for cve, entry in (self.doc["intel"] or {}).get("cves", {}).items():
            self.assertEqual(entry, self.ctx["intel"][cve])

    def test_carries_every_patch_now_and_weaponized_row_and_exact_counts(self):
        ids = {r[0] for r in self.doc["rows"]}
        p1 = [r[0] for r in self.rows if build_site.priority(r, self.ctx) == 1]
        weap = [r[0] for r in self.rows if build_site.facts(r, self.ctx)["weap"]]
        self.assertTrue(set(p1) <= ids and set(weap) <= ids)
        c = self.doc["counts"]
        self.assertEqual((c["cves"], c["p1"], c["weap"]), (len(self.rows), len(p1), len(weap)))
        self.assertEqual(c["poc"], sum(1 for r in self.rows if build_site.facts(r, self.ctx)["poc"]))

    def test_client_checks_pin_signature_and_cross_checks(self):
        app = (ROOT / "site" / "app.js").read_text(encoding="utf-8")
        for needle in ("j.manifest_sha256!==MSHA", "SIGNED===true&&ok!==true", "briefMismatch(b,RAW.idx,RAW.intel)",
                       "function ensure(i){if(!rows.length||LITE"):
            self.assertIn(needle, app)
        sign = (ROOT / "scripts" / "sign_manifest.py").read_text(encoding="utf-8")
        self.assertIn('"brief" / "briefing.json"', sign)


if __name__ == "__main__":
    unittest.main()
