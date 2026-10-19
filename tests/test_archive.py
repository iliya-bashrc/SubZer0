from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import archive  # noqa: E402
import build_site  # noqa: E402


class ArchiveTests(unittest.TestCase):
    def test_archive_keeps_notable_cves_and_survives_the_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            first = archive.update(ROOT / "public" / "snapshot", tmp / "none", tmp / "a1")
            self.assertGreater(first["count"], 0)
            records = archive.load(tmp / "a1")
            self.assertTrue(all(r["signals"]["p"] in (1, 2) for r in records.values()))
            # a CVE that has left the window must survive the next refresh
            month = first["months"][0]
            path = tmp / "a1" / month["path"]
            items = json.loads(path.read_bytes())
            ghost = dict(items[0], id="CVE-2001-99999", published="2001-01-01T00:00:00Z")
            items.append(ghost)
            raw = json.dumps(items).encode()
            path.write_bytes(raw)
            import hashlib
            idx = json.loads((tmp / "a1" / "index.json").read_text())
            idx["months"][0].update(count=len(items), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            idx["count"] += 1
            (tmp / "a1" / "index.json").write_text(json.dumps(idx))
            second = archive.update(ROOT / "public" / "snapshot", tmp / "a1", tmp / "a2")
            self.assertIn("CVE-2001-99999", archive.load(tmp / "a2"))
            self.assertEqual(second["count"], first["count"] + 1)
            out = tmp / "_site"
            build_site.build(ROOT / "site", ROOT / "public" / "snapshot", out, tmp / "a2")
            doc = (out / "cve" / "CVE-2001-99999.html").read_text(encoding="utf-8")
            self.assertIn('data-archived="CVE-2001-99999"', doc)
            self.assertIn("cve/CVE-2001-99999</loc>", (out / "sitemap.xml").read_text(encoding="utf-8"))

    def test_verify_rejects_tampering_and_stray_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            index = archive.update(ROOT / "public" / "snapshot", tmp / "none", tmp / "a")
            (tmp / "a" / "evil.json").write_text("[]")
            with self.assertRaises(archive.ArchiveError):
                archive.verify(tmp / "a")
            (tmp / "a" / "evil.json").unlink()
            path = tmp / "a" / index["months"][-1]["path"]
            path.write_bytes(path.read_bytes().replace(b'"CVE-', b'"CVF-', 1))
            with self.assertRaises(archive.ArchiveError):
                archive.verify(tmp / "a")


if __name__ == "__main__":
    unittest.main()
