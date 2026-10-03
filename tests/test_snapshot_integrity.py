from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import update_data as feed  # noqa: E402
from migrate_legacy_snapshot import migrate_snapshot  # noqa: E402
from verify_data_snapshot import SnapshotValidationError, validate_snapshot  # noqa: E402


class SnapshotIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "snapshot"
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self._create_fixture()

    def tearDown(self):
        self.temporary.cleanup()

    def _create_fixture(self):
        activity = feed.iso_z(self.now - timedelta(hours=1))
        cve = {
            "id": "CVE-2026-8001", "published": activity, "lastModified": activity,
            "descriptions": [{"lang": "en", "value": "A fixture vulnerability in Widget."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
            "references": [{"url": "https://vendor.example/security/8001"}],
        }
        advisory = {
            "ghsa_id": "GHSA-fixture-8001", "cve_id": "CVE-2026-8001",
            "summary": "Fixture advisory", "published_at": activity,
            "html_url": "https://github.com/advisories/GHSA-fixture-8001",
        }
        kev = {
            "cveID": "CVE-2026-8001", "dateAdded": self.now.date().isoformat(),
            "vendorProject": "Fixture", "product": "Widget", "dueDate": "",
            "requiredAction": "Apply the vendor update.", "knownRansomwareCampaignUse": "Unknown",
        }
        start = self.now - timedelta(days=30)
        records = feed.build_records([{"cve": cve}], [advisory], [kev], start, self.now)
        statuses = [
            {"name": "NVD CVE API 2.0", "ok": True, "records": 1, "pages": 1, "checked_at": feed.iso_z(self.now)},
            {"name": "GitHub Security Advisory Database", "ok": True, "advisories": 1, "pages": 1, "checked_at": feed.iso_z(self.now)},
            {"name": "CISA KEV", "ok": True, "catalog_records": 1, "checked_at": feed.iso_z(self.now)},
        ]
        manifest, shards = feed.build_manifest(records, start, self.now, self.now, statuses, 1, 1, 1)
        epss = {
            "schema_version": 1, "updated_at": feed.iso_z(self.now), "checked_at": feed.iso_z(self.now),
            "score_date": self.now.date().isoformat(), "source_updated_at": feed.iso_z(self.now), "error": "",
            "scores": {"CVE-2026-8001": {"score": 0.2, "percentile": 0.95}},
        }
        epss_status = {
            "name": "FIRST EPSS", "ok": True, "scores": 1, "records": 1,
            "score_date": self.now.date().isoformat(), "source_updated_at": feed.iso_z(self.now),
            "checked_at": feed.iso_z(self.now), "note": "",
        }
        feed.add_epss_metadata(manifest, epss, epss_status)
        feed.write_snapshot(self.root, manifest, shards, epss)

    def _manifest(self):
        return json.loads((self.root / "manifest.json").read_text(encoding="utf-8"))

    def _save_manifest(self, manifest):
        feed._write_json(self.root / "manifest.json", manifest)

    def _update_day(self, day: str, records: list[dict], raw: bytes | None = None):
        manifest = self._manifest()
        raw = raw if raw is not None else feed._json_bytes(records)
        summary = next(item for item in manifest["days"] if item["date"] == day)
        (self.root / summary["path"]).write_bytes(raw)
        summary["count"] = len(records)
        summary["bytes"] = len(raw)
        summary["sha256"] = hashlib.sha256(raw).hexdigest()
        for severity in feed.SEVERITY_ORDER:
            summary[severity] = sum(item.get("sev") == severity for item in records)
        summary["exploited"] = sum(bool(item.get("kev")) for item in records)
        self._save_manifest(manifest)
        return manifest

    def test_new_snapshot_and_report_validate(self):
        report = validate_snapshot(self.root, write_report=True)
        self.assertEqual(report["records"], 1)
        self.assertEqual(report["shards"], 31)
        self.assertEqual(report["epss_status"], "current")
        self.assertTrue((self.root / "VALIDATION.json").is_file())

    def test_legacy_metadata_migration_preserves_source_bytes_and_timestamp(self):
        day = next(item["date"] for item in self._manifest()["days"] if item["count"])
        source_path = self.root / "data" / f"{day}.json"
        source_records = json.loads(source_path.read_text(encoding="utf-8"))
        naive_utc = source_records[0]["activity_at"].removesuffix("Z")
        source_records[0]["published"] = naive_utc
        source_records[0]["modified"] = source_records[0]["published"]
        source_records[0]["activity_at"] = naive_utc
        self._update_day(day, source_records)
        legacy_root = Path(self.temporary.name) / "legacy"
        shutil.copytree(self.root, legacy_root)
        original_manifest = json.loads((legacy_root / "manifest.json").read_text(encoding="utf-8"))
        original_generated_at = original_manifest["generated_at"]
        original_bytes = {
            path.relative_to(legacy_root).as_posix(): path.read_bytes()
            for path in (legacy_root / "data").glob("*.json")
            if path.name != "overview.json"
        }
        (legacy_root / "data" / "overview.json").unlink()
        original_manifest.pop("overview", None)
        original_manifest["facets"] = {"path": "data/facets.json"}
        original_manifest["history"] = {"path": "data/history.json", "retention_days": 30}
        for summary in original_manifest["days"]:
            summary.pop("bytes", None)
        original_manifest["epss"].pop("bytes", None)
        original_manifest["epss"].pop("sha256", None)
        for status in original_manifest["source_status"]:
            if status["name"] != "FIRST EPSS":
                status.pop("checked_at", None)
        feed._write_json(legacy_root / "manifest.json", original_manifest)

        report = migrate_snapshot(legacy_root)
        migrated_manifest = json.loads((legacy_root / "manifest.json").read_text(encoding="utf-8"))
        after_bytes = {
            path.relative_to(legacy_root).as_posix(): path.read_bytes()
            for path in (legacy_root / "data").glob("*.json")
            if path.name != "overview.json"
        }
        self.assertEqual(after_bytes, original_bytes)
        self.assertEqual(migrated_manifest["generated_at"], original_generated_at)
        self.assertNotIn("facets", migrated_manifest)
        self.assertNotIn("history", migrated_manifest)
        self.assertTrue((legacy_root / "data" / "overview.json").is_file())
        self.assertEqual(report["records"], 1)
        self.assertEqual(validate_snapshot(legacy_root)["records"], 1)

    def test_real_checked_in_full_snapshot_validates(self):
        report = validate_snapshot(ROOT / "snapshot")
        self.assertEqual(report["records"], 15_318)
        self.assertEqual(report["shards"], 31)
        self.assertGreater(report["largest_shard_bytes"], 5_000_000)

    def test_tamper_without_recomputing_digest_is_rejected(self):
        manifest = self._manifest()
        day = next(item["date"] for item in manifest["days"] if item["count"])
        record_path = self.root / "data" / f"{day}.json"
        raw = record_path.read_bytes()
        record_path.write_bytes(raw.replace(b"Fixture", b"Tamper!", 1))
        with self.assertRaisesRegex(SnapshotValidationError, "SHA-256 mismatch"):
            validate_snapshot(self.root)

    def test_duplicate_json_keys_are_rejected_even_with_a_matching_hash(self):
        manifest = self._manifest()
        day = next(item["date"] for item in manifest["days"] if item["count"])
        duplicate = b'[{"id":"CVE-2026-8001","id":"CVE-2026-8002"}]\n'
        self._update_day(day, [], raw=duplicate)
        with self.assertRaisesRegex(SnapshotValidationError, "Duplicate JSON object key"):
            validate_snapshot(self.root)

    def test_unsafe_protocol_is_rejected_after_hashes_are_updated(self):
        manifest = self._manifest()
        day = next(item["date"] for item in manifest["days"] if item["count"])
        shard_path = self.root / "data" / f"{day}.json"
        records = json.loads(shard_path.read_text(encoding="utf-8"))
        records[0]["primary_url"] = "javascript:alert(1)"
        self._update_day(day, records)
        with self.assertRaisesRegex(SnapshotValidationError, r"HTTP\(S\) URL"):
            validate_snapshot(self.root)

    def test_safe_http_security_references_remain_valid(self):
        manifest = self._manifest()
        day = next(item["date"] for item in manifest["days"] if item["count"])
        shard_path = self.root / "data" / f"{day}.json"
        records = json.loads(shard_path.read_text(encoding="utf-8"))
        records[0]["refs"].append({"label": "Legacy vendor archive", "url": "http://vendor.example/archive", "source": "NVD"})
        self._update_day(day, records)
        self.assertEqual(validate_snapshot(self.root)["records"], 1)

    def test_manifest_traversal_unlisted_file_and_excessive_size_are_rejected(self):
        manifest = self._manifest()
        manifest["days"][0]["path"] = "../outside.json"
        self._save_manifest(manifest)
        with self.assertRaisesRegex(SnapshotValidationError, "Unexpected path"):
            validate_snapshot(self.root)

        self._create_fixture()
        (self.root / "data" / "obsolete.json").write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(SnapshotValidationError, "file set mismatch"):
            validate_snapshot(self.root)

        (self.root / "data" / "obsolete.json").unlink()
        manifest = self._manifest()
        manifest["days"][0]["bytes"] = 16 * 1024 * 1024 + 1
        self._save_manifest(manifest)
        with self.assertRaisesRegex(SnapshotValidationError, "integer between"):
            validate_snapshot(self.root)

    def test_overview_must_match_the_actual_newest_feed_records(self):
        manifest = self._manifest()
        overview_path = self.root / "data" / "overview.json"
        overview = json.loads(overview_path.read_text(encoding="utf-8"))
        overview["records"][0]["title"] = "Counterfeit homepage record"
        raw = feed._json_bytes(overview)
        overview_path.write_bytes(raw)
        manifest["overview"]["bytes"] = len(raw)
        manifest["overview"]["sha256"] = hashlib.sha256(raw).hexdigest()
        self._save_manifest(manifest)
        with self.assertRaisesRegex(SnapshotValidationError, "newest full-feed record"):
            validate_snapshot(self.root)


if __name__ == "__main__":
    unittest.main()
