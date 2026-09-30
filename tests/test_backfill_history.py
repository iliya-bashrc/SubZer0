import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import backfill_history


class BackfillHistoryTests(unittest.TestCase):
    def test_backfill_reads_actual_complete_git_snapshots_and_detects_material_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
            (root / "data").mkdir()
            record = {"id": "CVE-2026-4301", "score": 8.6, "kev": None}
            manifest = {
                "schema_version": 2,
                "complete": True,
                "generated_at": "2026-09-28T12:00:00Z",
                "totals": {"cves": 1},
                "epss": {"updated_at": "2026-09-28T12:00:00Z", "score_date": "2026-09-28"},
                "days": [{"date": "2026-09-28", "sha256": "first"}],
            }
            (root / "data/2026-09-28.json").write_text(json.dumps([record]))
            (root / "data/epss.json").write_text(json.dumps({"score_date": "2026-09-28", "scores": {"CVE-2026-4301": {"score": 0.02}}}))
            (root / "data/manifest.json").write_text(json.dumps(manifest))
            subprocess.run(["git", "add", "data"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "snapshot one"], cwd=root, check=True)

            record.update({"score": 9.4, "kev": {"date_added": "2026-09-29"}})
            manifest.update({
                "generated_at": "2026-09-29T12:00:00Z",
                "epss": {"updated_at": "2026-09-29T12:00:00Z", "score_date": "2026-09-29"},
                "days": [{"date": "2026-09-28", "sha256": "second"}],
            })
            (root / "data/2026-09-28.json").write_text(json.dumps([record]))
            (root / "data/epss.json").write_text(json.dumps({"score_date": "2026-09-29", "scores": {"CVE-2026-4301": {"score": 0.13}}}))
            (root / "data/manifest.json").write_text(json.dumps(manifest))
            subprocess.run(["git", "add", "data"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "snapshot two"], cwd=root, check=True)

            history = backfill_history.backfill(root)
            self.assertEqual(len(history["snapshots"]), 2)
            self.assertEqual({event["type"] for event in history["events"]}, {"severity", "kev_added", "epss_jump"})
            self.assertTrue(all(event["id"] == "CVE-2026-4301" for event in history["events"]))
            self.assertTrue((root / "data/history.json").is_file())


if __name__ == "__main__":
    unittest.main()
