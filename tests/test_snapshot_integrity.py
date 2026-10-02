import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.verify_data_snapshot import validate_snapshot  # noqa: E402


class SnapshotIntegrityTests(unittest.TestCase):
    def make_fixture(self, root: Path, records=None):
        data = root / "data"
        api = root / "api" / "v1"
        data.mkdir(parents=True)
        api.mkdir(parents=True)
        records = records or [{"id": "CVE-2024-1000", "score": 9.8, "kev": {"date_added": "2024-01-02"}}]
        raw = (json.dumps(records, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
        (data / "2024-01-02.json").write_bytes(raw)
        summary = {
            "date": "2024-01-02",
            "count": len(records),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "critical": len(records),
            "high": 0,
            "medium": 0,
            "low": 0,
            "none": 0,
            "unknown": 0,
            "exploited": len(records),
            "path": "data/2024-01-02.json",
        }
        manifest = {
            "schema_version": 2,
            "generated_at": "2024-01-02T12:00:00Z",
            "last_successful_update": "2024-01-02T12:00:00Z",
            "complete": True,
            "window": {"start": "2024-01-02T00:00:00Z", "end": "2024-01-02T12:00:00Z"},
            "coverage": {"sources_complete": True, "utc_days_sharded": 1, "distinct_cve_records": len(records)},
            "source_status": [
                {"name": "NVD CVE API 2.0", "ok": True},
                {"name": "GitHub Security Advisory Database", "ok": True},
                {"name": "CISA KEV", "ok": True},
                {"name": "FIRST EPSS", "ok": False, "note": "Stale"},
            ],
            "days": [summary],
            "totals": {"cves": len(records), "critical": len(records), "high": 0, "medium": 0, "low": 0, "none": 0, "unknown": 0, "known_exploited": len(records)},
            "facets": {"path": "data/facets.json"},
            "history": {"path": "data/history.json"},
            "epss": {"path": "data/epss.json", "score_date": "2024-01-02", "source_updated_at": "2024-01-02T11:00:00Z"},
        }
        for name, value in (
            (data / "manifest.json", manifest),
            (api / "manifest.json", manifest),
            (data / "facets.json", {"schema_version": 1, "vendors": [], "products": [], "product_pairs": []}),
            (data / "history.json", {"schema_version": 1, "snapshots": [], "events": []}),
            (data / "epss.json", {"schema_version": 1, "score_date": "2024-01-02", "scores": {}}),
        ):
            name.write_text(json.dumps(value, separators=(",", ":")) + "\n", encoding="utf-8")
        return manifest, raw

    def test_complete_snapshot_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_fixture(root)
            summary = validate_snapshot(root)
            self.assertEqual(summary["shards"], 1)
            self.assertEqual(summary["records"], 1)

    def test_modified_shard_fails_checksum(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_fixture(root)
            (root / "data" / "2024-01-02.json").write_bytes(b"[]\n")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                validate_snapshot(root)

    def test_manifest_count_must_match_verified_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, _ = self.make_fixture(root)
            manifest["days"][0]["count"] = 2
            for relative in ("data/manifest.json", "api/v1/manifest.json"):
                (root / relative).write_text(json.dumps(manifest) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Declared row count mismatch"):
                validate_snapshot(root)

    def test_duplicate_cve_within_shard_fails(self):
        record = {"id": "CVE-2024-1000", "score": 9.8, "kev": {"date_added": "2024-01-02"}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_fixture(root, [record, dict(record)])
            with self.assertRaisesRegex(ValueError, "Duplicate CVE ID inside"):
                validate_snapshot(root)


if __name__ == "__main__":
    unittest.main()
